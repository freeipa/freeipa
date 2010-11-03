#ifndef _SLAPI_PLUGINS_UTIL_H
#define _SLAPI_PLUGINS_UTIL_H

#define EOK 0
#define EFAIL -1

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define log_func discard_const(__func__)

#define LOG_PLUGIN_NAME(NAME, fmt, ...) \
    slapi_log_error(SLAPI_LOG_PLUGIN, \
                    NAME, \
                    fmt, ##__VA_ARGS__)

#define LOG(fmt, ...) \
    LOG_PLUGIN_NAME(IPA_PLUGIN_NAME, fmt, ##__VA_ARGS__)

#define LOG_CONFIG_NAME(NAME, fmt, ...) \
    slapi_log_error(SLAPI_LOG_CONFIG, \
                    NAME, \
                    fmt, ##__VA_ARGS__)

#define LOG_CONFIG(fmt, ...) \
    LOG_CONFIG_NAME(IPA_PLUGIN_NAME, fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    slapi_log_error(SLAPI_LOG_FATAL, log_func, \
                    "[file %s, line %d]: " fmt, \
                    __FILE__, __LINE__, ##__VA_ARGS__)

#define LOG_TRACE(fmt, ...) \
    slapi_log_error(SLAPI_LOG_TRACE, log_func, fmt, ##__VA_ARGS__)

#define LOG_OOM() LOG_FATAL("Out of Memory!\n")

#endif /* _SLAPI_PLUGINS_UTIL_H */
