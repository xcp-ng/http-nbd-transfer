/*
 * Copyright (C) 2022  Vates SAS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <curl/curl.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define NBDKIT_API_VERSION 2
#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_CONNECTIONS

#include <nbdkit-plugin.h>

// =============================================================================

#define UNUSED(X) (void)X;

#define BROKEN_PIPE_RETRY_COUNT 30
#define TIMEOUT_SERVER_TEST 3000L

// -----------------------------------------------------------------------------
// Config & handle.
// -----------------------------------------------------------------------------

typedef struct {
  // Mandatory.
  char *urls;

  // Optional.
  const char *user;
  char *password;
  size_t deviceSize;
  bool hasDeviceSize;

  // Internal.
  const char **urlArray;
  size_t urlArraySize;
  size_t urlArrayCapacity;
} GlobalConfig;
GlobalConfig Config;

typedef struct {
  CURL *curl;

  int readonly;

  char errBuf[CURL_ERROR_SIZE];

  const char *readBuf;
  size_t readCount;

  char *writeBuf;
  size_t writeCount;

  bool acceptRanges;

  int currentUrlId;
  size_t deviceSize;
} Handle;

// -----------------------------------------------------------------------------
// Log.
// -----------------------------------------------------------------------------

#define log_error(HANDLE, RES, MESSAGE, ...) do { \
  nbdkit_error((MESSAGE ": `%s` (%s)."), ## __VA_ARGS__, curl_easy_strerror((RES)), (HANDLE)->errBuf); \
} while (false)

// -----------------------------------------------------------------------------
// Conv helpers.
// -----------------------------------------------------------------------------

static size_t toSize (const char *str, bool *ok) {
  char *end;
  long long value = strtoll(str, &end, 10);

  if (ok)
    *ok = end != str && errno != ERANGE && value >= 0;

  return (size_t)value;
}

// -----------------------------------------------------------------------------
// Another implementation of some ctype functions to avoid usage of current
// locale.
// -----------------------------------------------------------------------------

static inline bool c_isspace (int c) {
  return c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f';
}

static inline bool c_isupper (int c) {
  return c >= 'A' && c <= 'Z';
}

static inline int c_tolower (int c) {
  return c_isupper(c) ? c - 'A' + 'a' : c;
}

static inline int c_strncasecmp (const char *s1, const char *s2, size_t n) {
  if (!n)
    return 0;

  const unsigned char *us1 = (const unsigned char *)s1;
  const unsigned char *us2 = (const unsigned char *)s2;

  do {
    if (c_tolower(*us1) != c_tolower(*us2))
      return c_tolower(*us1) - c_tolower(*us2);
    if (*us1++ == '\0')
      break;
    us2++;
  } while (--n != 0);

  return 0;
}

// -----------------------------------------------------------------------------
// cURL callbacks.
// -----------------------------------------------------------------------------

static size_t curl_cb_header (void *ptr, size_t size, size_t nmemb, void *userData) {
  static const char acceptRanges[] = "accept-ranges:";
  static const char bytes[] = "bytes";

  Handle *handle = userData;
  const size_t totalSize = size * nmemb;

  const char *headerBegin = ptr;
  const char *headerEnd = headerBegin + totalSize;

  if (totalSize >= sizeof acceptRanges - 1 && !c_strncasecmp(headerBegin, acceptRanges, sizeof acceptRanges - 1)) {
    const char *p = strchr(headerBegin, ':') + 1;
    while (p < headerEnd && *p && c_isspace(*p))
      p++;

    if ((size_t)(headerEnd - p) >= sizeof bytes - 1 && !strncmp(p, bytes, sizeof bytes - 1)) {
      p += sizeof bytes - 1;
      while (p < headerEnd && *p && c_isspace(*p))
        p++;

      if (p == headerEnd || !*p)
        handle->acceptRanges = true;
    }
  }

  return totalSize;
}

static size_t curl_cb_write (char *ptr, size_t size, size_t nmemb, void *userData) {
  Handle *handle = userData;
  assert(handle->writeBuf);

  const size_t totalSize = size * nmemb;
  size_t written = totalSize;
  if (written > handle->writeCount)
    written = handle->writeCount;

  memcpy(handle->writeBuf, ptr, written);
  handle->writeCount -= written;
  handle->writeBuf += written;

  return totalSize;
}

static size_t curl_cb_read (void *ptr, size_t size, size_t nmemb, void *userData) {
  Handle *handle = userData;
  assert(handle->readBuf);

  size_t read = size * nmemb;
  if (read > handle->readCount)
    read = handle->readCount;

  memcpy(ptr, handle->readBuf, read);
  handle->readCount -= read;
  handle->readBuf += read;

  return read;
}

// -----------------------------------------------------------------------------
// cURL perform call.
// -----------------------------------------------------------------------------

typedef enum  {
  ReqErrorOk,
  ReqErrorUnreachable,
  ReqErrorRange,
  ReqErrorReadWrite,
  ReqErrorUnknown
} ReqError;

static ReqError check_req_perform (Handle *handle, CURLcode code) {
  if (code == CURLE_OK)
    return ReqErrorOk;

  assert(handle->currentUrlId >= 0);
  const char *curUrl = Config.urlArray[handle->currentUrlId];
  #define log_req_error(MESSAGE) \
    log_error(handle, code, "Failed to execute request on `%s`, " MESSAGE, curUrl);

  switch (code) {
    case CURLE_COULDNT_CONNECT:
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
      log_req_error("unable to join");
      return ReqErrorUnreachable;
    case CURLE_RANGE_ERROR:
      log_req_error("range unsupported");
      return ReqErrorRange;
    case CURLE_BAD_DOWNLOAD_RESUME:
    case CURLE_GOT_NOTHING:
    case CURLE_PARTIAL_FILE:
    case CURLE_READ_ERROR:
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_UPLOAD_FAILED:
    case CURLE_WRITE_ERROR:
      log_req_error("bad read/write");
      return ReqErrorReadWrite;
    default:
      log_req_error("unknown");
      break;
  }

  #undef log_req_error

  return ReqErrorUnknown;
}

// -----------------------------------------------------------------------------
// Misc..
// -----------------------------------------------------------------------------

#define CHECK_CURL(FUNC) \
  do { \
    const CURLcode res = (FUNC); \
    if (res != CURLE_OK) { \
      nbdkit_error("cURL call error (" #FUNC "): `%s`.", curl_easy_strerror(res)); \
      goto err; \
    } \
  } while (false)

static void decr_url_id (Handle *handle) {
  handle->currentUrlId = (handle->currentUrlId + (int)Config.urlArraySize - 1) % (int)Config.urlArraySize;
}

static void inc_url_id (Handle *handle) {
  handle->currentUrlId = (handle->currentUrlId + 1) % (int)Config.urlArraySize;
}

static int select_server (Handle *handle, int limitUrlId, int serverCount) {
  const int maxServerCount = (int)Config.urlArraySize;
  if (serverCount <= 0 || serverCount > maxServerCount)
    serverCount = maxServerCount;

  double deviceSize = 0.0;

  if (handle->curl)
    curl_easy_cleanup(handle->curl);

  handle->curl = curl_easy_init();
  if (!handle->curl) {
    nbdkit_error("Failed to initialize curl: %m.");
    return -1;
  }
  CURL *curl = handle->curl;

  // Configure cURL.
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, handle->errBuf));

  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_NOBODY, 1L));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1L));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L));

  const long protocols = CURLPROTO_HTTP | CURLPROTO_HTTPS;
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_PROTOCOLS, protocols));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, protocols));

  // Optional config.
  if (Config.user)
    CHECK_CURL(curl_easy_setopt(curl, CURLOPT_USERNAME, Config.user));
  if (Config.password)
    CHECK_CURL(curl_easy_setopt(curl, CURLOPT_PASSWORD, Config.password));

  // Find device size.
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_cb_header));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_HEADERDATA, handle));

  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_READDATA, NULL));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL));

  for (inc_url_id(handle); serverCount--; inc_url_id(handle)) {
    const int urlId = handle->currentUrlId;
    assert(urlId >= 0);

    if (urlId == limitUrlId)
      break;

    const char *url = Config.urlArray[urlId];
    nbdkit_debug("Trying to use server: `%s`...", url);

    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
      log_error(handle, res, "Cannot use URL `%s`", url);
      continue;
    }

    res = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_SERVER_TEST);
    if (res != CURLE_OK) {
      log_error(handle, res, "Cannot set timeout on `%s`", url);
      continue;
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      log_error(handle, res, "Cannot exec head request properly on `%s`", url);
      continue;
    }

    if (!handle->acceptRanges) {
      nbdkit_error("Server `%s` doesn't support range requests.", url);
      continue;
    }

    res = curl_easy_getinfo(handle->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &deviceSize);
    if (res != CURLE_OK) {
      log_error(handle, res, "Failed to get size of backing device on `%s`", url);
      continue;
    }

    if (deviceSize > 0.0) {
      // Success. \o/
      break;
    }

    nbdkit_error("Invalid backing device size on `%s`.", url);
    continue;
  }

  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, NULL));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL));

  if (deviceSize <= 0.0) {
    handle->currentUrlId = -1;
    return -1;
  }

  // Configure cURL to read/write.
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_cb_read));
  CHECK_CURL(curl_easy_setopt(curl, CURLOPT_READDATA, handle));

  if (!handle->readonly) {
    CHECK_CURL(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb_write));
    CHECK_CURL(curl_easy_setopt(curl, CURLOPT_WRITEDATA, handle));
  }

  nbdkit_debug("Selected server: `%s`.", Config.urlArray[handle->currentUrlId]);
  handle->deviceSize = (size_t)deviceSize;
  nbdkit_debug("Device size: %" PRIi64 ".", handle->deviceSize);

  return 0;

err:
  return -1;
}

static inline int reconnect_current_server (Handle *handle) {
  decr_url_id(handle);
  return select_server(handle, -1, 1);
}

static inline int auto_select_server_until_id (Handle *handle, int limitUrlId) {
  return select_server(handle, limitUrlId, -1);
}

static inline int auto_select_server (Handle *handle) {
  return select_server(handle, -1, -1);
}

// -----------------------------------------------------------------------------
// Plugin implementation.
// -----------------------------------------------------------------------------

static void cb_load () {
  CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (res != CURLE_OK) {
    nbdkit_error("Failed to initialize curl: %d.", (int)res);
    exit(EXIT_FAILURE);
  }
}

static void cb_unload () {
  free(Config.urls);
  free(Config.urlArray);
  free(Config.password);
  curl_global_cleanup();
}

static int cb_config (const char *key, const char *value) {
  if (!strcmp(key, "urls")) {
    free(Config.urls);
    Config.urls = strdup(value);
  } else if (!strcmp(key, "user")) {
    Config.user = value;
  } else if (!strcmp(key, "password")) {
    free(Config.password);
    if (nbdkit_read_password(value, &Config.password) == -1)
      return -1;
  } else if (!strcmp(key, "device-size")) {
    bool ok;
    Config.deviceSize = toSize(value, &ok);
    if (!ok) {
      nbdkit_error("Invalid device size!");
      return -1;
    }
    Config.hasDeviceSize = true;
  } else {
    nbdkit_error("Unknown parameter: `%s`.", key);
    return -1;
  }

  return 0;
}

static int cb_config_complete () {
  if (!Config.urls) {
    nbdkit_error("`urls` params must be given.");
    return -1;
  }

  Config.urlArrayCapacity = 16;
  if (!(Config.urlArray = malloc(sizeof *Config.urlArray * Config.urlArrayCapacity))) {
    nbdkit_error("Failed to allocate URL array.");
    return -1;
  }

  char *url = strtok(Config.urls, ",");
  while (url) {
    while (c_isspace(*url))
      ++url;

    char *end = url + strlen(url);
    while (url != end && c_isspace(*(end - 1)))
      --end;

    if (url != end) {
      *end = '\0';

      if (++Config.urlArraySize > Config.urlArrayCapacity) {
        Config.urlArrayCapacity <<= 1;

        void *ptr = realloc(Config.urlArray, Config.urlArrayCapacity);
        if (!ptr) {
          nbdkit_error("Failed to reallocate URL array.");
          return -1;
        }
        Config.urlArray = ptr;
      }

      Config.urlArray[Config.urlArraySize - 1] = url;
    }

    url = strtok(NULL, ",");
  }

  if (!Config.urlArraySize) {
    nbdkit_error("`urls` doesn't contain URLs.");
    return -1;
  }

  return 0;
}

static void *cb_open (int readonly) {
  Handle *handle = calloc(1, sizeof *handle);
  if (!handle) {
    nbdkit_error("Failed to allocate handle.");
    return NULL;
  }

  handle->readonly = readonly;
  handle->currentUrlId = -1;

  // In any case we must return a valid handle. So if we can't reach a server and if the device size
  // is not given using the command line, it's problematic. We must exit.
  if (auto_select_server(handle) < 0) {
    nbdkit_error("Failed to select a server at startup.");

    if (!Config.hasDeviceSize) {
      nbdkit_error("No device size, exit!");
      free(handle);
      return NULL;
    }
  }

  if (Config.hasDeviceSize)
    handle->deviceSize = Config.deviceSize;

  return handle;
}

static void cb_close (void *userData) {
  Handle *handle = userData;
  if (handle) {
    curl_easy_cleanup(handle->curl);
    free(handle);
  }
}

static int64_t cb_get_size (void *userData) {
  // Called only one time after the open call. So the device size must always be valid.
  return (int64_t)((Handle *)userData)->deviceSize;
}

#define exec_op(HANDLE, OPTION, COUNT, OFFSET, RES) do { \
  assert(COUNT); \
  CHECK_CURL(curl_easy_setopt((HANDLE)->curl, (OPTION), 1L)); \
  \
  char range[128]; \
  snprintf(range, sizeof range, "%" PRIu64 "-%" PRIu64, OFFSET, (OFFSET) + (COUNT) - 1); \
  CHECK_CURL(curl_easy_setopt((HANDLE)->curl, CURLOPT_RANGE, range)); \
  \
  (RES) = check_req_perform((HANDLE), curl_easy_perform((HANDLE)->curl)); \
} while (false)

static int cb_pread (void *userData, void *buf, uint32_t count, uint64_t offset, uint32_t flags) {
  UNUSED(flags);

  Handle *handle = userData;
  if (handle->currentUrlId < 0) {
    nbdkit_debug("Reconnecting...");
    if (auto_select_server(handle) < 0) {
      nbdkit_error("Cannot exec read request, no valid server found.");
      return -1;
    }
  }

  const int firstUrlId = handle->currentUrlId;
  assert(firstUrlId >= 0);

  for (int retryCount = BROKEN_PIPE_RETRY_COUNT; ; ) {
    handle->writeBuf = buf;
    handle->writeCount = count;

    ReqError result;
    exec_op(handle, CURLOPT_HTTPGET, count, offset, result);
    if (result == ReqErrorOk) {
      if (!handle->writeCount)
        return 0;
      nbdkit_error("Incomplete read request, retry on another server.");
    }

    if (result == ReqErrorReadWrite && retryCount > 0) {
      --retryCount;
      nbdkit_error("Failed to read, maybe a connection reset. Retrying...");
      if (reconnect_current_server(handle) >= 0)
        continue;
      nbdkit_error("Failed to reconnect with current server.");
    }

    nbdkit_error("Failed to read, trying another server...");
    if (auto_select_server_until_id(handle, firstUrlId) < 0) {
      nbdkit_error("Cannot re-exec read request, no valid server found.");
      return -1;
    }
  }

  return 0;

err:
  return -1;
}

static int cb_pwrite (void *userData, const void *buf, uint32_t count, uint64_t offset, uint32_t flags) {
  UNUSED(flags);

  Handle *handle = userData;
  if (handle->currentUrlId < 0) {
    nbdkit_debug("Reconnecting...");
    if (auto_select_server(handle) < 0) {
      nbdkit_error("Cannot exec write request, no valid server found.");
      return -1;
    }
  }

  const int firstUrlId = handle->currentUrlId;
  assert(firstUrlId >= 0);

  for (int retryCount = BROKEN_PIPE_RETRY_COUNT; ; ) {
    handle->readBuf = buf;
    handle->readCount = count;

    ReqError result;
    exec_op(handle, CURLOPT_UPLOAD, count, offset, result);
    if (result == ReqErrorOk) {
      if (!handle->readCount)
        return 0;
      nbdkit_error("Incomplete write request, retry on another server.");
    }

    if (result == ReqErrorReadWrite && retryCount > 0) {
      --retryCount;
      nbdkit_error("Failed to write, maybe a connection reset. Retrying...");
      if (reconnect_current_server(handle) >= 0)
        continue;
      nbdkit_error("Failed to reconnect with current server.");
    }

    nbdkit_error("Failed to write, trying another server...");
    if (auto_select_server_until_id(handle, firstUrlId) < 0) {
      nbdkit_error("Cannot re-exec write request, no valid server found.");
      return -1;
    }
  }

  return 0;

err:
  return -1;
}

#undef exec_op

// -----------------------------------------------------------------------------

#define cb_config_help \
  "urls=<URL,...>  (required) Comma separated list of URLs to use"

static struct nbdkit_plugin plugin = {
  .name              = "multihttp",
  .longname          = NULL,
  .description       = NULL,
  .version           = "1.0.0",
  .load              = cb_load,
  .unload            = cb_unload,
  .dump_plugin       = NULL,
  .config            = cb_config,
  .config_complete   = cb_config_complete,
  .config_help       = cb_config_help,
  .magic_config_key  = "urls",
  .open              = cb_open,
  .close             = cb_close,
  .get_size          = cb_get_size,
  .can_write         = NULL,
  .can_flush         = NULL,
  .is_rotational     = NULL,
  .can_trim          = NULL,
  .can_zero          = NULL,
  .can_fua           = NULL,
  .pread             = cb_pread,
  .pwrite            = cb_pwrite,
  .flush             = NULL,
  .trim              = NULL,
  .zero              = NULL,
  .errno_is_preserved = 1
};

#undef cb_config_help

NBDKIT_REGISTER_PLUGIN(plugin)
