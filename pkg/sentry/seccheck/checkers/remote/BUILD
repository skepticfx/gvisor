load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "remote",
    srcs = ["remote.go"],
    marshal = True,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//types/known/anypb:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
