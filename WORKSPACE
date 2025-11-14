load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "68af54cb97fbdee5e5e8fe8d210d15a518f9d62abfd71620c3eaff3b26a5ff86",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.59.0/rules_go-v0.59.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.59.0/rules_go-v0.59.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "675114d8b433d0a9f54d81171833be96ebc4113115664b791e6f204d58e93446",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.47.0/bazel-gazelle-v0.47.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.47.0/bazel-gazelle-v0.47.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(version = "1.25.4")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

go_repository(
    name = "com_github_golang_jwt_jwt_v4",
    importpath = "github.com/golang-jwt/jwt/v4",
    sum = "h1:YtQM7lnr8iZ+j5q71MGKkNw9Mn7AjHM68uc9g5fXeUI=",
    version = "v4.5.2",
)

go_repository(
    name = "co_honnef_go_tools",
    importpath = "honnef.co/go/tools",
    sum = "h1:4bH5o3b5ZULQ4UrBmP+63W9r7qIkqJClEA9ko5YKx+I=",
    version = "v0.5.1",
)

go_repository(
    name = "com_github_bazelbuild_rules_go",
    importpath = "github.com/bazelbuild/rules_go",
    sum = "h1:H2nzlC9VLKeVW1D90bahFSszpDE5qvtKr95Nz7BN0WQ=",
    version = "v0.44.2",
)

go_repository(
    name = "com_github_burntsushi_toml",
    importpath = "github.com/BurntSushi/toml",
    sum = "h1:pxW6RcqyfI9/kWtOwnv/G+AzdKuy2ZrqINhenH4HyNs=",
    version = "v1.4.1-0.20240526193622-a339e1f7089c",
)

go_repository(
    name = "com_github_cenkalti_backoff",
    importpath = "github.com/cenkalti/backoff",
    sum = "h1:tNowT99t7UNflLxfYYSlKYsBpXdEet03Pg2g16Swow4=",
    version = "v2.2.1+incompatible",
)

go_repository(
    name = "com_github_chzyer_readline",
    importpath = "github.com/chzyer/readline",
    sum = "h1:upd/6fQk4src78LMRzh5vItIt361/o4uq553V8B5sGI=",
    version = "v1.5.1",
)

go_repository(
    name = "com_github_cilium_ebpf",
    importpath = "github.com/cilium/ebpf",
    sum = "h1:8ht6F9MquybnY97at+VDZb3eQQr8ev79RueWeVaEcG4=",
    version = "v0.12.3",
)

go_repository(
    name = "com_github_containerd_cgroups",
    importpath = "github.com/containerd/cgroups",
    sum = "h1:jN/mbWBEaz+T1pi5OFtnkQ+8qnmEbAr1Oo1FRm5B0dA=",
    version = "v1.0.4",
)

go_repository(
    name = "com_github_containerd_console",
    importpath = "github.com/containerd/console",
    sum = "h1:lIr7SlA5PxZyMV30bDW0MGbiOPXwc63yRuCP0ARubLw=",
    version = "v1.0.3",
)

go_repository(
    name = "com_github_containerd_containerd",
    importpath = "github.com/containerd/containerd",
    sum = "h1:Bcj0ZXqgIs6GG+YbaKkMX3Dap0JsIVG4UYFOLRo7iX4=",
    version = "v1.6.36",
)

go_repository(
    name = "com_github_containerd_continuity",
    importpath = "github.com/containerd/continuity",
    sum = "h1:nisirsYROK15TAMVukJOUyGJjz4BNQJBVsNvAXZJ/eg=",
    version = "v0.3.0",
)

go_repository(
    name = "com_github_containerd_errdefs",
    importpath = "github.com/containerd/errdefs",
    sum = "h1:m0wCRBiu1WJT/Fr+iOoQHMQS/eP5myQ8lCv4Dz5ZURM=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_containerd_fifo",
    importpath = "github.com/containerd/fifo",
    sum = "h1:6PirWBr9/L7GDamKr+XM0IeUFXu5mf3M/BPpH9gaLBU=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_containerd_go_runc",
    importpath = "github.com/containerd/go-runc",
    sum = "h1:oU+lLv1ULm5taqgV/CJivypVODI4SUz1znWjv3nNYS0=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_containerd_log",
    importpath = "github.com/containerd/log",
    sum = "h1:TCJt7ioM2cr/tfR8GPbGf9/VRAX8D2B4PjzCpfX540I=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_containerd_ttrpc",
    importpath = "github.com/containerd/ttrpc",
    sum = "h1:4jH6OQDQqjfVD2b5TJS5TxmGuLGmp5WW7KtW2TWOP7c=",
    version = "v1.1.2",
)

go_repository(
    name = "com_github_containerd_typeurl",
    importpath = "github.com/containerd/typeurl",
    sum = "h1:Chlt8zIieDbzQFzXzAeBEF92KhExuE4p9p92/QmY7aY=",
    version = "v1.0.2",
)

go_repository(
    name = "com_github_coreos_go_systemd_v22",
    importpath = "github.com/coreos/go-systemd/v22",
    sum = "h1:RrqgGjYQKalulkV8NGVIfkXQf6YYmOyiJKk8iXXhfZs=",
    version = "v22.5.0",
)

go_repository(
    name = "com_github_cpuguy83_go_md2man_v2",
    importpath = "github.com/cpuguy83/go-md2man/v2",
    sum = "h1:XJtiaUW6dEEqVuZiMTn1ldk455QWwEIsMIJlo5vtkx0=",
    version = "v2.0.6",
)

go_repository(
    name = "com_github_davecgh_go_spew",
    importpath = "github.com/davecgh/go-spew",
    sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_docker_go_events",
    importpath = "github.com/docker/go-events",
    sum = "h1:+pKlWGMw7gf6bQ+oDZB4KHQFypsfjYlq/C4rfL7D3g8=",
    version = "v0.0.0-20190806004212-e31b211e4f1c",
)

go_repository(
    name = "com_github_docker_go_units",
    importpath = "github.com/docker/go-units",
    sum = "h1:3uh0PgVws3nIA0Q+MwDC8yjEPf9zjRfZZWXZYDct3Tw=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_gkampitakis_ciinfo",
    importpath = "github.com/gkampitakis/ciinfo",
    sum = "h1:JcuOPk8ZU7nZQjdUhctuhQofk7BGHuIy0c9Ez8BNhXs=",
    version = "v0.3.2",
)

go_repository(
    name = "com_github_gkampitakis_go_diff",
    importpath = "github.com/gkampitakis/go-diff",
    sum = "h1:Qyn0J9XJSDTgnsgHRdz9Zp24RaJeKMUHg2+PDZZdC4M=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_gkampitakis_go_snaps",
    importpath = "github.com/gkampitakis/go-snaps",
    sum = "h1:amyJrvM1D33cPHwVrjo9jQxX8g/7E2wYdZ+01KS3zGE=",
    version = "v0.5.15",
)

go_repository(
    name = "com_github_go_logr_logr",
    importpath = "github.com/go-logr/logr",
    sum = "h1:CjnDlHq8ikf6E492q6eKboGOC0T8CDaOvkHCIg8idEI=",
    version = "v1.4.3",
)

go_repository(
    name = "com_github_go_task_slim_sprig_v3",
    importpath = "github.com/go-task/slim-sprig/v3",
    sum = "h1:sUs3vkvUymDpBKi3qH1YSqBQk9+9D/8M2mN1vB6EwHI=",
    version = "v3.0.0",
)

go_repository(
    name = "com_github_goccy_go_yaml",
    importpath = "github.com/goccy/go-yaml",
    sum = "h1:8W7wMFS12Pcas7KU+VVkaiCng+kG8QiFeFwzFb+rwuw=",
    version = "v1.18.0",
)

go_repository(
    name = "com_github_godbus_dbus_v5",
    importpath = "github.com/godbus/dbus/v5",
    sum = "h1:4KLkAxT3aOY8Li4FRJe/KvhoNFFxo0m6fNuFUO8QJUk=",
    version = "v5.1.0",
)

go_repository(
    name = "com_github_gofrs_flock",
    importpath = "github.com/gofrs/flock",
    sum = "h1:MSdYClljsF3PbENUUEx85nkWfJSGfzYI9yEBZOJz6CY=",
    version = "v0.8.0",
)

go_repository(
    name = "com_github_gogo_googleapis",
    importpath = "github.com/gogo/googleapis",
    sum = "h1:zgVt4UpGxcqVOw97aRGxT4svlcmdK35fynLNctY32zI=",
    version = "v1.4.0",
)

go_repository(
    name = "com_github_gogo_protobuf",
    importpath = "github.com/gogo/protobuf",
    sum = "h1:Ov1cvc58UF3b5XjBnZv7+opcTcQFZebYjWzi34vdm4Q=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_golang_groupcache",
    importpath = "github.com/golang/groupcache",
    sum = "h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=",
    version = "v0.0.0-20210331224755-41bb18bfe9da",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    sum = "h1:YojYx61/OLFsiv6Rw1Z96LpldJIy31o+UHmwAUMJ6/U=",
    version = "v1.7.0-rc.1",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    sum = "h1:i7eJL8qZTpSEXOPTxNKhASYpMn+8e5Q6AdndVa1dWek=",
    version = "v1.5.4",
)

go_repository(
    name = "com_github_google_btree",
    importpath = "github.com/google/btree",
    sum = "h1:xf4v41cLI2Z6FxbKm+8Bu+m8ifhj15JuZ9sa0jZCMUU=",
    version = "v1.1.2",
)

go_repository(
    name = "com_github_google_go_cmp",
    importpath = "github.com/google/go-cmp",
    sum = "h1:wk8382ETsv4JYUZwIsn6YpYiWiBsYLSJiTsyBybVuN8=",
    version = "v0.7.0",
)

go_repository(
    name = "com_github_google_go_github_v56",
    importpath = "github.com/google/go-github/v56",
    sum = "h1:TysL7dMa/r7wsQi44BjqlwaHvwlFlqkK8CtBWCX3gb4=",
    version = "v56.0.0",
)

go_repository(
    name = "com_github_google_gofuzz",
    importpath = "github.com/google/gofuzz",
    sum = "h1:xRy4A+RhZaiKjJ1bPfwQ8sedCA+YS2YcCHW6ec7JMi0=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_google_pprof",
    importpath = "github.com/google/pprof",
    sum = "h1:BHT72Gu3keYf3ZEu2J0b1vyeLSOYI8bm5wbJM/8yDe8=",
    version = "v0.0.0-20250403155104-27863c87afa6",
)

go_repository(
    name = "com_github_google_subcommands",
    importpath = "github.com/google/subcommands",
    sum = "h1:8nlgEAjIalk6uj/CGKCdOO8CQqTeysvcW4RFZ6HbkGM=",
    version = "v1.0.2-0.20190508160503-636abe8753b8",
)

go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:KjJaJ9iWZ3jOFZIf1Lqf4laDRCasjl0BCmnEGxkdLb4=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_googleapis_gnostic",
    importpath = "github.com/googleapis/gnostic",
    sum = "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
    version = "v0.5.5",
)

go_repository(
    name = "com_github_hanwen_go_fuse_v2",
    importpath = "github.com/hanwen/go-fuse/v2",
    sum = "h1:t5ivNIH2PK+zw4OBul/iJjsoG9K6kXo4nMDoBpciC8A=",
    version = "v2.3.0",
)

go_repository(
    name = "com_github_hashicorp_errwrap",
    importpath = "github.com/hashicorp/errwrap",
    sum = "h1:OxrOeh75EUXMY8TBjag2fzXGZ40LB6IKw45YeGUDY2I=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_hashicorp_go_multierror",
    importpath = "github.com/hashicorp/go-multierror",
    sum = "h1:H5DkEtf6CXdFp0N0Em5UCwQpXMWke8IA0+lD48awMYo=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_ianlancetaylor_demangle",
    importpath = "github.com/ianlancetaylor/demangle",
    sum = "h1:KwWnWVWCNtNq/ewIX7HIKnELmEx2nDP42yskD/pi7QE=",
    version = "v0.0.0-20240312041847-bd984b5ce465",
)

go_repository(
    name = "com_github_inconshreveable_mousetrap",
    importpath = "github.com/inconshreveable/mousetrap",
    sum = "h1:wN+x4NVGpMsO7ErUn/mUI3vEoE6Jt13X2s0bqwp9tc8=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_josharian_native",
    importpath = "github.com/josharian/native",
    sum = "h1:uuaP0hAbW7Y4l0ZRQ6C9zfb7Mg1mbFKry/xzDAfmtLA=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_joshdk_go_junit",
    importpath = "github.com/joshdk/go-junit",
    sum = "h1:S86cUKIdwBHWwA6xCmFlf3RTLfVXYQfvanM5Uh+K6GE=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_json_iterator_go",
    importpath = "github.com/json-iterator/go",
    sum = "h1:PV8peI4a0ysnczrg+LtxykD8LfKY9ML6u2jnxaEnrnM=",
    version = "v1.1.12",
)

go_repository(
    name = "com_github_klauspost_compress",
    importpath = "github.com/klauspost/compress",
    sum = "h1:wKRjX6JRtDdrE9qwa4b/Cip7ACOshUI4smpCQanqjSY=",
    version = "v1.15.9",
)

go_repository(
    name = "com_github_kr_pretty",
    importpath = "github.com/kr/pretty",
    sum = "h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=",
    version = "v0.3.1",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    sum = "h1:hyz3dwM5QLc1Rfoz4FuWJQG5BN7tc6K1MndAUnGpQr4=",
    version = "v1.1.5",
)

go_repository(
    name = "com_github_kr_text",
    importpath = "github.com/kr/text",
    sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_maruel_natural",
    importpath = "github.com/maruel/natural",
    sum = "h1:Hja7XhhmvEFhcByqDoHz9QZbkWey+COd9xWfCfn1ioo=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_masterminds_semver_v3",
    importpath = "github.com/Masterminds/semver/v3",
    sum = "h1:Zog+i5UMtVoCU8oKka5P7i9q9HgrJeGzI9SA1Xbatp0=",
    version = "v3.4.0",
)

go_repository(
    name = "com_github_mattbaird_jsonpatch",
    importpath = "github.com/mattbaird/jsonpatch",
    sum = "h1:+J2gw7Bw77w/fbK7wnNJJDKmw1IbWft2Ul5BzrG1Qm8=",
    version = "v0.0.0-20171005235357-81af80346b1a",
)

go_repository(
    name = "com_github_mattn_go_colorable",
    importpath = "github.com/mattn/go-colorable",
    sum = "h1:fFA4WZxdEF4tXPZVKMLwD8oUnCTTo08duU7wxecdEvA=",
    version = "v0.1.13",
)

go_repository(
    name = "com_github_mattn_go_isatty",
    importpath = "github.com/mattn/go-isatty",
    sum = "h1:JITubQf0MOLdlGRuRq+jtsDlekdYPia9ZFsB8h/APPA=",
    version = "v0.0.19",
)

go_repository(
    name = "com_github_mdlayher_genetlink",
    importpath = "github.com/mdlayher/genetlink",
    sum = "h1:KdrNKe+CTu+IbZnm/GVUMXSqBBLqcGpRDa0xkQy56gw=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_mdlayher_netlink",
    importpath = "github.com/mdlayher/netlink",
    sum = "h1:/UtM3ofJap7Vl4QWCPDGXY8d3GIY2UGSDbK+QWmY8/g=",
    version = "v1.7.2",
)

go_repository(
    name = "com_github_mdlayher_socket",
    importpath = "github.com/mdlayher/socket",
    sum = "h1:VZaqt6RkGkt2OE9l3GcC6nZkqD3xKeQLyfleW/uBcos=",
    version = "v0.5.1",
)

go_repository(
    name = "com_github_mfridman_tparse",
    importpath = "github.com/mfridman/tparse",
    sum = "h1:wh6dzOKaIwkUGyKgOntDW4liXSo37qg5AXbIhkMV3vE=",
    version = "v0.18.0",
)

go_repository(
    name = "com_github_microsoft_go_winio",
    importpath = "github.com/Microsoft/go-winio",
    sum = "h1:slsWYD/zyx7lCXoZVlvQrj0hPTM1HI4+v1sIda2yDvg=",
    version = "v0.6.0",
)

go_repository(
    name = "com_github_microsoft_hcsshim",
    importpath = "github.com/Microsoft/hcsshim",
    sum = "h1:0Wgl1fRF4WmBuqP6EnHk2w3m7CCCumD/KUumZxp7vKg=",
    version = "v0.9.12",
)

go_repository(
    name = "com_github_mikioh_ipaddr",
    importpath = "github.com/mikioh/ipaddr",
    sum = "h1:RlZweED6sbSArvlE924+mUcZuXKLBHA35U7LN621Bws=",
    version = "v0.0.0-20190404000644-d465c8ab6721",
)

go_repository(
    name = "com_github_moby_locker",
    importpath = "github.com/moby/locker",
    sum = "h1:fOXqR41zeveg4fFODix+1Ch4mj/gT0NE1XJbp/epuBg=",
    version = "v1.0.1",
)

go_repository(
    name = "com_github_moby_sys_capability",
    importpath = "github.com/moby/sys/capability",
    sum = "h1:4D4mI6KlNtWMCM1Z/K0i7RV1FkX+DBDHKVJpCndZoHk=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_moby_sys_mountinfo",
    importpath = "github.com/moby/sys/mountinfo",
    sum = "h1:BzJjoreD5BMFNmD9Rus6gdd1pLuecOFPt8wC+Vygl78=",
    version = "v0.6.2",
)

go_repository(
    name = "com_github_moby_sys_signal",
    importpath = "github.com/moby/sys/signal",
    sum = "h1:aDpY94H8VlhTGa9sNYUFCFsMZIUh5wm0B6XkIoJj/iY=",
    version = "v0.6.0",
)

go_repository(
    name = "com_github_moby_sys_user",
    importpath = "github.com/moby/sys/user",
    sum = "h1:WmZ93f5Ux6het5iituh9x2zAG7NFY9Aqi49jjE1PaQg=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_modern_go_concurrent",
    importpath = "github.com/modern-go/concurrent",
    sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
    version = "v0.0.0-20180306012644-bacd9c7ef1dd",
)

go_repository(
    name = "com_github_modern_go_reflect2",
    importpath = "github.com/modern-go/reflect2",
    sum = "h1:xBagoLtFs94CBntxluKeaWgTMpvLxC4ur3nMaC9Gz0M=",
    version = "v1.0.2",
)

go_repository(
    name = "com_github_mohae_deepcopy",
    importpath = "github.com/mohae/deepcopy",
    sum = "h1:Sha2bQdoWE5YQPTlJOL31rmce94/tYi113SlFo1xQ2c=",
    version = "v0.0.0-20170308212314-bb9b5e7adda9",
)

go_repository(
    name = "com_github_onsi_ginkgo_v2",
    importpath = "github.com/onsi/ginkgo/v2",
    sum = "h1:LzwLj0b89qtIy6SSASkzlNvX6WktqurSHwkk2ipF/Ns=",
    version = "v2.27.2",
)

go_repository(
    name = "com_github_onsi_gomega",
    importpath = "github.com/onsi/gomega",
    sum = "h1:eZCjf2xjZAqe+LeWvKb5weQ+NcPwX84kqJ0cZNxok2A=",
    version = "v1.38.2",
)

go_repository(
    name = "com_github_opencontainers_go_digest",
    importpath = "github.com/opencontainers/go-digest",
    sum = "h1:apOUWs51W5PlhuyGyz9FCeeBIOUDA/6nW8Oi/yOhh5U=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_opencontainers_image_spec",
    importpath = "github.com/opencontainers/image-spec",
    sum = "h1:8SG7/vwALn54lVB/0yZ/MMwhFrPYtpEHQb2IpWsCzug=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_opencontainers_runtime_spec",
    importpath = "github.com/opencontainers/runtime-spec",
    sum = "h1:wHa9jroFfKGQqFHj0I1fMRKLl0pfj+ynAqBxo3v6u9w=",
    version = "v1.1.0-rc.1",
)

go_repository(
    name = "com_github_opencontainers_selinux",
    importpath = "github.com/opencontainers/selinux",
    sum = "h1:09LIPVRP3uuZGQvgR+SgMSNBd1Eb3vlRbGqQpoHsF8w=",
    version = "v1.10.1",
)

go_repository(
    name = "com_github_pkg_errors",
    importpath = "github.com/pkg/errors",
    sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
    version = "v0.9.1",
)

go_repository(
    name = "com_github_pmezard_go_difflib",
    importpath = "github.com/pmezard/go-difflib",
    sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_rogpeppe_go_internal",
    importpath = "github.com/rogpeppe/go-internal",
    sum = "h1:KvO1DLK/DRN07sQ1LQKScxyZJuNnedQ5/wKSR38lUII=",
    version = "v1.13.1",
)

go_repository(
    name = "com_github_rs_xid",
    importpath = "github.com/rs/xid",
    sum = "h1:fV591PaemRlL6JfRxGDEPl69wICngIQ3shQtzfy2gxU=",
    version = "v1.6.0",
)

go_repository(
    name = "com_github_rs_zerolog",
    importpath = "github.com/rs/zerolog",
    sum = "h1:k43nTLIwcTVQAncfCw4KZ2VY6ukYoZaBPNOE8txlOeY=",
    version = "v1.34.0",
)

go_repository(
    name = "com_github_russross_blackfriday_v2",
    importpath = "github.com/russross/blackfriday/v2",
    sum = "h1:JIOH55/0cWyOuilr9/qlrm0BSXldqnqwMsf35Ld67mk=",
    version = "v2.1.0",
)

go_repository(
    name = "com_github_sirupsen_logrus",
    importpath = "github.com/sirupsen/logrus",
    sum = "h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=",
    version = "v1.9.3",
)

go_repository(
    name = "com_github_spf13_cobra",
    importpath = "github.com/spf13/cobra",
    sum = "h1:lJeBwCfmrnXthfAupyUTzJ/J4Nc1RsHC/mSRU2dll/s=",
    version = "v1.10.1",
)

go_repository(
    name = "com_github_spf13_pflag",
    importpath = "github.com/spf13/pflag",
    sum = "h1:9exaQaMOCwffKiiiYk6/BndUBv+iRViNW+4lEMi0PvY=",
    version = "v1.0.9",
)

go_repository(
    name = "com_github_stretchr_testify",
    importpath = "github.com/stretchr/testify",
    sum = "h1:CcVxjf3Q8PM0mHUKJCdn+eZZtm5yQwehR5yeSVQQcUk=",
    version = "v1.8.4",
)

go_repository(
    name = "com_github_tidwall_gjson",
    importpath = "github.com/tidwall/gjson",
    sum = "h1:FIDeeyB800efLX89e5a8Y0BNH+LOngJyGrIWxG2FKQY=",
    version = "v1.18.0",
)

go_repository(
    name = "com_github_tidwall_match",
    importpath = "github.com/tidwall/match",
    sum = "h1:+Ho715JplO36QYgwN9PGYNhgZvoUSc9X2c80KVTi+GA=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_tidwall_pretty",
    importpath = "github.com/tidwall/pretty",
    sum = "h1:qjsOFOWWQl+N3RsoF5/ssm1pHmJJwhjlSbZ51I6wMl4=",
    version = "v1.2.1",
)

go_repository(
    name = "com_github_tidwall_sjson",
    importpath = "github.com/tidwall/sjson",
    sum = "h1:kLy8mja+1c9jlljvWTlSazM7cKDRfJuR/bOJhcY5NcY=",
    version = "v1.2.5",
)

go_repository(
    name = "com_github_vishvananda_netlink",
    importpath = "github.com/vishvananda/netlink",
    sum = "h1:8mhqcHPqTMhSPoslhGYihEgSfc77+7La1P6kiB6+9So=",
    version = "v1.1.1-0.20211118161826-650dca95af54",
)

go_repository(
    name = "com_github_vishvananda_netns",
    importpath = "github.com/vishvananda/netns",
    sum = "h1:p4VB7kIXpOQvVn1ZaTIVp+3vuYAXFe3OJEvjbUYJLaA=",
    version = "v0.0.0-20210104183010-2eb08e3e575f",
)

go_repository(
    name = "com_github_yuin_goldmark",
    importpath = "github.com/yuin/goldmark",
    sum = "h1:fVcFKWvrslecOb/tg+Cc05dkeYx540o0FuFt3nUVDoE=",
    version = "v1.4.13",
)

go_repository(
    name = "com_zx2c4_golang_wintun",
    importpath = "golang.zx2c4.com/wintun",
    sum = "h1:B82qJJgjvYKsXS9jeunTOisW56dUokqW/FOteYJJ/yg=",
    version = "v0.0.0-20230126152724-0fa3db229ce2",
)

go_repository(
    name = "com_zx2c4_golang_wireguard",
    importpath = "golang.zx2c4.com/wireguard",
    sum = "h1:whnFRlWMcXI9d+ZbWg+4sHnLp52d5yiIPUxMBSt4X9A=",
    version = "v0.0.0-20250521234502-f333402bd9cb",
)

go_repository(
    name = "com_zx2c4_golang_wireguard_wgctrl",
    importpath = "golang.zx2c4.com/wireguard/wgctrl",
    sum = "h1:3GDAcqdIg1ozBNLgPy4SLT84nfcBjr6rhGtXYtrkWLU=",
    version = "v0.0.0-20241231184526-a9ab2273dd10",
)

go_repository(
    name = "dev_gvisor_gvisor",
    importpath = "gvisor.dev/gvisor",
    sum = "h1:m/r7OM+Y2Ty1sgBQ7Qb27VgIMBW8ZZhT4gLnUyDIhzI=",
    version = "v0.0.0-20250503011706-39ed1f5ac29c",
)

go_repository(
    name = "in_gopkg_check_v1",
    importpath = "gopkg.in/check.v1",
    sum = "h1:qIbj1fsPNlZgppZ+VLlY7N33q108Sa+fhmuc+sWQYwY=",
    version = "v1.0.0-20180628173108-788fd7840127",
)

go_repository(
    name = "in_gopkg_inf_v0",
    importpath = "gopkg.in/inf.v0",
    sum = "h1:73M5CoZyi3ZLMOyDlQh031Cx6N9NDJ2Vvfl76EDAgDc=",
    version = "v0.9.1",
)

go_repository(
    name = "in_gopkg_tomb_v1",
    importpath = "gopkg.in/tomb.v1",
    sum = "h1:uRGJdciOHaEIrze2W8Q3AKkepLTh2hOroT7a+7czfdQ=",
    version = "v1.0.0-20141024135613-dd632973f1e7",
)

go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
    version = "v2.4.0",
)

go_repository(
    name = "in_gopkg_yaml_v3",
    importpath = "gopkg.in/yaml.v3",
    sum = "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
    version = "v3.0.1",
)

go_repository(
    name = "in_yaml_go_yaml_v3",
    importpath = "go.yaml.in/yaml/v3",
    sum = "h1:tfq32ie2Jv2UxXFdLJdh3jXuOzWiL1fo0bu/FbuKpbc=",
    version = "v3.0.4",
)

go_repository(
    name = "io_k8s_api",
    importpath = "k8s.io/api",
    sum = "h1:op+yeqZLQxDt2tEnrOP9Y+WA7l4Lxh+7R0IWEzyuk2I=",
    version = "v0.23.16",
)

go_repository(
    name = "io_k8s_apimachinery",
    importpath = "k8s.io/apimachinery",
    sum = "h1:f6Q+3qYv3qWvbDZp2iUhwC2rzMRBkSb7JYBhmeVK5pc=",
    version = "v0.23.16",
)

go_repository(
    name = "io_k8s_client_go",
    importpath = "k8s.io/client-go",
    sum = "h1:9NyRabEbkE9/7Rc3ZI8kMYfH3kocUD+wEBifaTn6lyU=",
    version = "v0.23.16",
)

go_repository(
    name = "io_k8s_klog_v2",
    importpath = "k8s.io/klog/v2",
    sum = "h1:bUO6drIvCIsvZ/XFgfxoGFQU/a4Qkh0iAlvUR7vlHJw=",
    version = "v2.30.0",
)

go_repository(
    name = "io_k8s_kube_openapi",
    importpath = "k8s.io/kube-openapi",
    sum = "h1:E3J9oCLlaobFUqsjG9DfKbP2BmgwBL2p7pn0A3dG9W4=",
    version = "v0.0.0-20211115234752-e816edb12b65",
)

go_repository(
    name = "io_k8s_sigs_json",
    importpath = "sigs.k8s.io/json",
    sum = "h1:fD1pz4yfdADVNfFmcP2aBEtudwUQ1AlLnRBALr33v3s=",
    version = "v0.0.0-20211020170558-c049b76a60c6",
)

go_repository(
    name = "io_k8s_sigs_structured_merge_diff_v4",
    importpath = "sigs.k8s.io/structured-merge-diff/v4",
    sum = "h1:PRbqxJClWWYMNV1dhaG4NsibJbArud9kFxnAMREiWFE=",
    version = "v4.2.3",
)

go_repository(
    name = "io_k8s_sigs_yaml",
    importpath = "sigs.k8s.io/yaml",
    sum = "h1:kr/MCeFWJWTwyaHoR9c8EjH9OumOmoF9YGiZd7lFm/Q=",
    version = "v1.2.0",
)

go_repository(
    name = "io_k8s_utils",
    importpath = "k8s.io/utils",
    sum = "h1:ck1fRPWPJWsMd8ZRFsWc6mh/zHp5fZ/shhbrgPUxDAE=",
    version = "v0.0.0-20211116205334-6203023598ed",
)

go_repository(
    name = "io_opencensus_go",
    importpath = "go.opencensus.io",
    sum = "h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=",
    version = "v0.24.0",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    sum = "h1:FZR1q0exgwxzPzp/aF+VccGrSfxfPpkBqjIIEq3ru6c=",
    version = "v1.6.7",
)

go_repository(
    name = "org_golang_google_genproto",
    importpath = "google.golang.org/genproto",
    sum = "h1:vlzZttNJGVqTsRFU9AmdnrcO1Znh8Ew9kCD//yjigk0=",
    version = "v0.0.0-20230920204549-e6e6cdab5c13",
)

go_repository(
    name = "org_golang_google_genproto_googleapis_rpc",
    importpath = "google.golang.org/genproto/googleapis/rpc",
    sum = "h1:6GQBEOdGkX6MMTLT9V+TjtIRZCw9VPD5Z+yHY9wMgS0=",
    version = "v0.0.0-20231002182017-d307bd883b97",
)

go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:Z5Iec2pjwb+LEOqzpB2MR12/eKFhDPhuqW91O+4bwUk=",
    version = "v1.59.0",
)

go_repository(
    name = "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
    importpath = "google.golang.org/grpc/cmd/protoc-gen-go-grpc",
    sum = "h1:rNBFJjBCOgVr9pWD7rs/knKL4FRTKgpZmsRfV214zcA=",
    version = "v1.3.0",
)

go_repository(
    name = "org_golang_google_protobuf",
    importpath = "google.golang.org/protobuf",
    sum = "h1:IgrO7UwFQGJdRNXH/sQux4R1Dj1WAKcLElzeeRaXV2A=",
    version = "v1.36.7",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:WKYxWedPGCTVVl5+WHSSrOBT0O8lx32+zxmHxijgXp4=",
    version = "v0.41.0",
)

go_repository(
    name = "org_golang_x_exp",
    importpath = "golang.org/x/exp",
    sum = "h1:Di6/M8l0O2lCLc6VVRWhgCiApHV8MnQurBnFSHsQtNY=",
    version = "v0.0.0-20230725093048-515e97ebf090",
)

go_repository(
    name = "org_golang_x_mod",
    importpath = "golang.org/x/mod",
    sum = "h1:kb+q2PyFnEADO2IEF935ehFUXlWiNjJWtRNgBLSfbxQ=",
    version = "v0.27.0",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:lat02VYK2j4aLzMzecihNvTlJNQUq316m2Mr9rnM6YE=",
    version = "v0.43.0",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:PbgcYx2W7i4LvjJWEbf0ngHV6qJYr86PkAV3bXdLEbs=",
    version = "v0.23.0",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:ycBJEhp9p4vXvUZNszeOq0kGTPghopOL8q0fq3vstxw=",
    version = "v0.16.0",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:vz1N37gP5bs89s7He8XuIYXpyY0+QlsKmzipCbUtyxI=",
    version = "v0.35.0",
)

go_repository(
    name = "org_golang_x_telemetry",
    importpath = "golang.org/x/telemetry",
    sum = "h1:3doPGa+Gg4snce233aCWnbZVFsyFMo/dR40KK/6skyE=",
    version = "v0.0.0-20250807160809-1a19826ec488",
)

go_repository(
    name = "org_golang_x_term",
    importpath = "golang.org/x/term",
    sum = "h1:O/2T7POpk0ZZ7MAzMeWFSg6S5IpWd/RXDlM9hgM3DR4=",
    version = "v0.34.0",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:rhazDwis8INMIwQ4tpjLDzUhx6RlXqZNPEM0huQojng=",
    version = "v0.28.0",
)

go_repository(
    name = "org_golang_x_time",
    importpath = "golang.org/x/time",
    sum = "h1:ntUhktv3OPE6TgYxXWv9vKvUSJyIFJlyohwbkEwPrKQ=",
    version = "v0.7.0",
)

go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:kWS0uv/zsvHEle1LbV5LE8QujrxB3wfQyxHfhOk0Qkg=",
    version = "v0.36.0",
)

go_repository(
    name = "org_golang_x_xerrors",
    importpath = "golang.org/x/xerrors",
    sum = "h1:H2TDz8ibqkAF6YGhCdN3jS9O0/s90v0rJh3X/OLHEUk=",
    version = "v0.0.0-20220907171357-04be3eba64a2",
)

go_repository(
    name = "org_uber_go_automaxprocs",
    importpath = "go.uber.org/automaxprocs",
    sum = "h1:O3y2/QNTOdbF+e/dpXNNW7Rx2hZ4sTIPyybbxyNqTUs=",
    version = "v1.6.0",
)

go_repository(
    name = "tools_gotest_v3",
    importpath = "gotest.tools/v3",
    sum = "h1:ZazjZUfuVeZGLAmlKKuyv3IKP5orXcwtOwDQH6YVr6o=",
    version = "v3.4.0",
)

gazelle_dependencies()
