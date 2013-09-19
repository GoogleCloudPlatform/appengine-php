licenses(["unencumbered"])  # Google copyright

package(
    default_visibility = ["//visibility:private"],
    features = [
        "crosstool_annotalysis",
    ],
)

cc_test(
    name = "connection_test",
    size = "small",
    srcs = ["connection_test.cc"],
    deps = [
        "//base:heapcheck",
        "//testing/base/public",
        "//third_party/openssl:ssl",
        "//thread",
    ],
)

cc_test(
    name = "reneg_unittest",
    size = "small",
    srcs = ["reneg_unittest.cc"],
    data = [
        "test.crt",
        "test.key",
    ],
    deps = [
        "//base:heapcheck",
        "//testing/base/public",
        "//third_party/openssl:ssl",
        "//thread",
    ],
)

cc_test(
    name = "select_certificate_cb_test",
    size = "small",
    srcs = ["select_certificate_cb_test.cc"],
    deps = [
        "//base",
        "//base:heapcheck",
        "//testing/base/public",
        "//third_party/openssl:ssl",
    ],
)

cc_test(
    name = "gcm_unittest",
    size = "small",
    srcs = ["gcm_unittest.cc"],
    deps = [
        "//base",
        "//base:heapcheck",
        "//testing/base/public",
        "//third_party/openssl:crypto",
    ],
)

cc_test(
    name = "err_unittest",
    size = "small",
    srcs = ["err_unittest.cc"],
    deps = [
        "//base",
        "//base:heapcheck",
        "//testing/base/public",
        "//third_party/openssl:crypto",
    ],
)
