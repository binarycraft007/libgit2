const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libgit_src = b.dependency("libgit2", .{});
    const libgit_root = libgit_src.path(".");

    const lib = b.addStaticLibrary(.{
        .name = "git2",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const features = b.addConfigHeader(
        .{ .style = .{ .cmake = libgit_src.path("src/util/git2_features.h.in") } },
        .{
            .GIT_THREADS = 1,

            // @Todo: add per target conditionals for these
            .GIT_USE_NSEC = 1,
            .GIT_USE_STAT_MTIM = 1,
            .GIT_RAND_GETENTROPY = 1,
            .GIT_RAND_GETLOADAVG = 1,
        },
    );

    const flags = [_][]const u8{
        // @Todo: for some reason on linux, trying to use c90 as specified in the cmake
        // files causes compile errors relating to pthreads. Using gnu90 or the
        // default compiles, so I guess this is fine?
        // "-std=c90",
        "-DHAVE_CONFIG_H",
        if (target.result.os.tag != .windows)
            "-DGIT_DEFAULT_CERT_LOCATION=\"/etc/ssl/certs/\""
        else
            "",
        "-fno-sanitize=undefined",
    };

    if (target.result.os.tag == .windows) {
        lib.linkSystemLibrary("winhttp");
        lib.linkSystemLibrary("rpcrt4");
        lib.linkSystemLibrary("crypt32");
        lib.linkSystemLibrary("ole32");
        lib.linkSystemLibrary("ws2_32");
        lib.linkSystemLibrary("secur32");

        features.addValues(.{
            .GIT_HTTPS = 1,
            .GIT_WINHTTP = 1,

            .GIT_SHA1_WIN32 = 1,
            .GIT_SHA256_WIN32 = 1,

            .GIT_IO_WSAPOLL = 1,
        });

        lib.addWin32ResourceFile(.{ .file = libgit_src.path("src/libgit2/git2.rc") });
        lib.addCSourceFiles(.{ .root = libgit_root, .files = &util_win32_sources, .flags = &flags });
    } else {
        features.addValues(.{
            .GIT_HTTPS = 1,
            .GIT_OPENSSL = 1,
            .GIT_OPENSSL_DYNAMIC = 1,
            .GIT_SHA1_OPENSSL = 1,
            .GIT_SHA256_OPENSSL = 1,

            .GIT_USE_FUTIMENS = 1,
            .GIT_IO_POLL = 1,
            .GIT_IO_SELECT = 1,
        });

        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &util_unix_sources,
            .flags = &flags,
        });
        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &.{
                "src/util/hash/openssl.c",
            },
            .flags = &flags,
        });
    }

    features.addValues(.{
        .GIT_SSH = 1,
        .GIT_SSH_EXEC = 1,
        .GIT_SSH_LIBSSH2_MEMORY_CREDENTIALS = 1, // @Todo: check for `libssh2_userauth_publickey_frommemory`?
    });

    // Bundled dependencies
    {
        const llhttp = b.addStaticLibrary(.{
            .name = "llhttp",
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        llhttp.addIncludePath(libgit_src.path("deps/llhttp"));
        llhttp.addCSourceFiles(.{
            .root = libgit_root,
            .files = &llhttp_sources,
            .flags = &.{ "-Wno-unused-parameter", "-Wno-missing-declarations" },
        });

        lib.addIncludePath(libgit_src.path("deps/llhttp"));
        lib.linkLibrary(llhttp);
        features.addValues(.{ .GIT_HTTPPARSER_BUILTIN = 1 });
    }
    {
        const pcre = b.addStaticLibrary(.{
            .name = "pcre",
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        pcre.root_module.addConfigHeader(b.addConfigHeader(
            .{ .style = .{ .cmake = libgit_src.path("deps/pcre/config.h.in") } },
            .{
                .SUPPORT_PCRE8 = 1,
                .PCRE_LINK_SIZE = 2,
                .PCRE_PARENS_NEST_LIMIT = 250,
                .PCRE_MATCH_LIMIT = 10000000,
                .PCRE_MATCH_LIMIT_RECURSION = "MATCH_LIMIT",
                .PCREGREP_BUFSIZE = 20480,
                .NEWLINE = 10, // LF
                .NO_RECURSE = 1,
                .PCRE_POSIX_MALLOC_THRESHOLD = 10,
                .BSR_ANYCRLF = 0,
                // "-DMAX_NAME_SIZE=32",
                // "-DMAX_NAME_COUNT=10000",
            },
        ));
        pcre.addIncludePath(libgit_src.path("deps/pcre"));
        pcre.addCSourceFiles(.{
            .root = libgit_root,
            .files = &pcre_sources,
            .flags = &.{
                "-Wno-unused-function",
                "-Wno-implicit-fallthrough",
                "-DHAVE_CONFIG_H",
            },
        });

        lib.addIncludePath(libgit_src.path("deps/pcre"));
        lib.linkLibrary(pcre);
        features.addValues(.{ .GIT_REGEX_BUILTIN = 1 });
    }
    {
        // @Todo: support using system zlib?
        const zlib = b.addStaticLibrary(.{
            .name = "z",
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        zlib.addIncludePath(libgit_src.path("deps/zlib"));
        zlib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &zlib_sources,
            .flags = &.{
                "-Wno-implicit-fallthrough",
                "-DNO_VIZ",
                "-DSTDC",
                "-DNO_GZIP",
                "-DHAVE_SYS_TYPES_H",
                "-DHAVE_STDINT_H",
                "-DHAVE_STDDEF_H",
            },
        });

        lib.addIncludePath(libgit_src.path("deps/zlib"));
        lib.linkLibrary(zlib);
    }
    // xdiff
    {
        // Bundled xdiff dependency relies on libgit2 headers & utils, so we
        // just add the source files directly instead of making a static lib step.

        // (Note from CMakeLists file:
        // the xdiff dependency is not (yet) warning-free, disable warnings
        // as errors for the xdiff sources until we've sorted them out)
        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &xdiff_sources,
            .flags = &.{ "-Wno-sign-compare", "-Wno-unused-parameter" },
        });
        lib.addIncludePath(libgit_src.path("deps/xdiff"));
    }

    switch (target.result.ptrBitWidth()) {
        32 => features.addValues(.{ .GIT_ARCH_32 = 1 }),
        64 => features.addValues(.{ .GIT_ARCH_64 = 1 }),
        else => |size| std.debug.panic("Unsupported architecture ({d}bit)", .{size}),
    }

    // @Todo: ICONV?

    lib.addConfigHeader(features);

    lib.addIncludePath(libgit_src.path("src/libgit2"));
    lib.addIncludePath(libgit_src.path("src/util"));
    lib.addIncludePath(libgit_src.path("include"));

    lib.addCSourceFiles(.{ .root = libgit_root, .files = &libgit_sources, .flags = &flags });
    lib.addCSourceFiles(.{ .root = libgit_root, .files = &util_sources, .flags = &flags });

    lib.installHeadersDirectory(libgit_src.path("include"), "", .{});
    b.installArtifact(lib);

    const translate_c = b.addTranslateC(.{
        .root_source_file = libgit_src.path("include/git2.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addIncludePath(libgit_src.path("include"));
    const git2_mod = translate_c.addModule("git2");
    git2_mod.linkLibrary(lib);

    const tests_step = b.step("run-tests", "Tests");
    {
        const tests = b.addTest(.{
            .root_source_file = b.path("tests/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        tests.root_module.addImport("git2", git2_mod);

        const fixture = b.addOptions();
        fixture.addOptionPath("resources", libgit_src.path("tests/resources"));

        tests.root_module.addOptions("fixture", fixture);

        tests.addConfigHeader(features);
        tests.addIncludePath(libgit_src.path("include"));
        tests.addIncludePath(libgit_src.path("src/util"));

        const tests_run = b.addRunArtifact(tests);
        tests_step.dependOn(&tests_run.step);
    }
}

const libgit_sources = [_][]const u8{
    "src/libgit2/annotated_commit.c",
    "src/libgit2/apply.c",
    "src/libgit2/attr.c",
    "src/libgit2/attr_file.c",
    "src/libgit2/attrcache.c",
    "src/libgit2/blame.c",
    "src/libgit2/blame_git.c",
    "src/libgit2/blob.c",
    "src/libgit2/branch.c",
    "src/libgit2/buf.c",
    "src/libgit2/cache.c",
    "src/libgit2/checkout.c",
    "src/libgit2/cherrypick.c",
    "src/libgit2/clone.c",
    "src/libgit2/commit.c",
    "src/libgit2/commit_graph.c",
    "src/libgit2/commit_list.c",
    "src/libgit2/config.c",
    "src/libgit2/config_cache.c",
    "src/libgit2/config_file.c",
    "src/libgit2/config_list.c",
    "src/libgit2/config_mem.c",
    "src/libgit2/config_parse.c",
    "src/libgit2/config_snapshot.c",
    "src/libgit2/crlf.c",
    "src/libgit2/delta.c",
    "src/libgit2/describe.c",
    "src/libgit2/diff.c",
    "src/libgit2/diff_driver.c",
    "src/libgit2/diff_file.c",
    "src/libgit2/diff_generate.c",
    "src/libgit2/diff_parse.c",
    "src/libgit2/diff_print.c",
    "src/libgit2/diff_stats.c",
    "src/libgit2/diff_tform.c",
    "src/libgit2/diff_xdiff.c",
    "src/libgit2/email.c",
    "src/libgit2/fetch.c",
    "src/libgit2/fetchhead.c",
    "src/libgit2/filter.c",
    "src/libgit2/grafts.c",
    "src/libgit2/graph.c",
    "src/libgit2/hashsig.c",
    "src/libgit2/ident.c",
    "src/libgit2/index_map.c",
    "src/libgit2/ignore.c",
    "src/libgit2/index.c",
    "src/libgit2/indexer.c",
    "src/libgit2/iterator.c",
    "src/libgit2/libgit2.c",
    "src/libgit2/mailmap.c",
    "src/libgit2/merge.c",
    "src/libgit2/merge_driver.c",
    "src/libgit2/merge_file.c",
    "src/libgit2/message.c",
    "src/libgit2/midx.c",
    "src/libgit2/mwindow.c",
    "src/libgit2/notes.c",
    "src/libgit2/object.c",
    "src/libgit2/object_api.c",
    "src/libgit2/odb.c",
    "src/libgit2/odb_loose.c",
    "src/libgit2/odb_mempack.c",
    "src/libgit2/odb_pack.c",
    "src/libgit2/oid.c",
    "src/libgit2/oidarray.c",
    "src/libgit2/pack-objects.c",
    "src/libgit2/pack.c",
    "src/libgit2/parse.c",
    "src/libgit2/patch.c",
    "src/libgit2/patch_generate.c",
    "src/libgit2/patch_parse.c",
    "src/libgit2/path.c",
    "src/libgit2/pathspec.c",
    "src/libgit2/proxy.c",
    "src/libgit2/push.c",
    "src/libgit2/reader.c",
    "src/libgit2/rebase.c",
    "src/libgit2/refdb.c",
    "src/libgit2/refdb_fs.c",
    "src/libgit2/reflog.c",
    "src/libgit2/refs.c",
    "src/libgit2/refspec.c",
    "src/libgit2/remote.c",
    "src/libgit2/repository.c",
    "src/libgit2/reset.c",
    "src/libgit2/revert.c",
    "src/libgit2/revparse.c",
    "src/libgit2/revwalk.c",
    "src/libgit2/settings.c",
    "src/libgit2/signature.c",
    "src/libgit2/stash.c",
    "src/libgit2/status.c",
    "src/libgit2/strarray.c",
    "src/libgit2/streams/mbedtls.c",
    "src/libgit2/streams/openssl.c",
    "src/libgit2/streams/openssl_dynamic.c",
    "src/libgit2/streams/openssl_legacy.c",
    "src/libgit2/streams/registry.c",
    "src/libgit2/streams/schannel.c",
    "src/libgit2/streams/socket.c",
    "src/libgit2/streams/stransport.c",
    "src/libgit2/streams/tls.c",
    "src/libgit2/submodule.c",
    "src/libgit2/sysdir.c",
    "src/libgit2/tag.c",
    "src/libgit2/trace.c",
    "src/libgit2/trailer.c",
    "src/libgit2/transaction.c",
    "src/libgit2/transport.c",
    "src/libgit2/transports/auth.c",
    "src/libgit2/transports/auth_gssapi.c",
    "src/libgit2/transports/auth_ntlmclient.c",
    "src/libgit2/transports/auth_sspi.c",
    "src/libgit2/transports/credential.c",
    "src/libgit2/transports/credential_helpers.c",
    "src/libgit2/transports/git.c",
    "src/libgit2/transports/http.c",
    "src/libgit2/transports/httpclient.c",
    "src/libgit2/transports/httpparser.c",
    "src/libgit2/transports/local.c",
    "src/libgit2/transports/smart.c",
    "src/libgit2/transports/smart_pkt.c",
    "src/libgit2/transports/smart_protocol.c",
    "src/libgit2/transports/ssh.c",
    "src/libgit2/transports/ssh_exec.c",
    "src/libgit2/transports/ssh_libssh2.c",
    "src/libgit2/transports/winhttp.c",
    "src/libgit2/tree-cache.c",
    "src/libgit2/tree.c",
    "src/libgit2/worktree.c",
};

const util_sources = [_][]const u8{
    "src/util/alloc.c",
    "src/util/allocators/failalloc.c",
    "src/util/allocators/stdalloc.c",
    "src/util/allocators/win32_leakcheck.c",
    "src/util/date.c",
    "src/util/errors.c",
    "src/util/filebuf.c",
    "src/util/fs_path.c",
    "src/util/futils.c",
    "src/util/hash.c",
    "src/util/net.c",
    "src/util/pool.c",
    "src/util/posix.c",
    "src/util/pqueue.c",
    "src/util/rand.c",
    "src/util/regexp.c",
    "src/util/runtime.c",
    "src/util/sortedcache.c",
    "src/util/str.c",
    "src/util/strlist.c",
    "src/util/thread.c",
    "src/util/tsort.c",
    "src/util/utf8.c",
    "src/util/util.c",
    "src/util/varint.c",
    "src/util/vector.c",
    "src/util/wildmatch.c",
    "src/util/zstream.c",
};

const util_unix_sources = [_][]const u8{
    "src/util/unix/map.c",
    "src/util/unix/process.c",
    "src/util/unix/realpath.c",
};

const util_win32_sources = [_][]const u8{
    "src/util/win32/dir.c",
    "src/util/win32/error.c",
    "src/util/win32/map.c",
    "src/util/win32/path_w32.c",
    "src/util/win32/posix_w32.c",
    "src/util/win32/precompiled.c",
    "src/util/win32/process.c",
    "src/util/win32/thread.c",
    "src/util/win32/utf-conv.c",
    "src/util/win32/w32_buffer.c",
    "src/util/win32/w32_leakcheck.c",
    "src/util/win32/w32_util.c",

    "src/util/hash/win32.c",
};

const llhttp_sources = [_][]const u8{
    "deps/llhttp/api.c",
    "deps/llhttp/http.c",
    "deps/llhttp/llhttp.c",
};

const pcre_sources = [_][]const u8{
    "deps/pcre/pcre_byte_order.c",
    "deps/pcre/pcre_chartables.c",
    "deps/pcre/pcre_compile.c",
    "deps/pcre/pcre_config.c",
    "deps/pcre/pcre_dfa_exec.c",
    "deps/pcre/pcre_exec.c",
    "deps/pcre/pcre_fullinfo.c",
    "deps/pcre/pcre_get.c",
    "deps/pcre/pcre_globals.c",
    "deps/pcre/pcre_jit_compile.c",
    "deps/pcre/pcre_maketables.c",
    "deps/pcre/pcre_newline.c",
    "deps/pcre/pcre_ord2utf8.c",
    "deps/pcre/pcre_printint.c",
    "deps/pcre/pcre_refcount.c",
    "deps/pcre/pcre_string_utils.c",
    "deps/pcre/pcre_study.c",
    "deps/pcre/pcre_tables.c",
    "deps/pcre/pcre_ucd.c",
    "deps/pcre/pcre_valid_utf8.c",
    "deps/pcre/pcre_version.c",
    "deps/pcre/pcre_xclass.c",
    "deps/pcre/pcreposix.c",
};

const zlib_sources = [_][]const u8{
    "deps/zlib/adler32.c",
    "deps/zlib/crc32.c",
    "deps/zlib/deflate.c",
    "deps/zlib/infback.c",
    "deps/zlib/inffast.c",
    "deps/zlib/inflate.c",
    "deps/zlib/inftrees.c",
    "deps/zlib/trees.c",
    "deps/zlib/zutil.c",
};

const xdiff_sources = [_][]const u8{
    "deps/xdiff/xdiffi.c",
    "deps/xdiff/xemit.c",
    "deps/xdiff/xhistogram.c",
    "deps/xdiff/xmerge.c",
    "deps/xdiff/xpatience.c",
    "deps/xdiff/xprepare.c",
    "deps/xdiff/xutils.c",
};

const ntlm_sources = [_][]const u8{
    "deps/ntlmclient/crypt_builtin_md4.c",
    "deps/ntlmclient/ntlm.c",
    "deps/ntlmclient/unicode_builtin.c",
    "deps/ntlmclient/util.c",
};

const cli_sources = [_][]const u8{
    "src/cli/cmd.c",
    "src/cli/cmd_cat_file.c",
    "src/cli/cmd_clone.c",
    "src/cli/cmd_config.c",
    "src/cli/cmd_hash_object.c",
    "src/cli/cmd_help.c",
    "src/cli/cmd_index_pack.c",
    "src/cli/common.c",
    "src/cli/main.c",
    "src/cli/opt.c",
    "src/cli/opt_usage.c",
    "src/cli/progress.c",
};

const cli_win32_sources = [_][]const u8{
    "src/cli/win32/sighandler.c",
};

const cli_unix_sources = [_][]const u8{
    "src/cli/unix/sighandler.c",
};

const example_sources = [_][]const u8{
    "examples/add.c",
    "examples/args.c",
    "examples/blame.c",
    "examples/cat-file.c",
    "examples/checkout.c",
    "examples/clone.c",
    "examples/commit.c",
    "examples/common.c",
    "examples/config.c",
    "examples/describe.c",
    "examples/diff.c",
    "examples/fetch.c",
    "examples/for-each-ref.c",
    "examples/general.c",
    "examples/index-pack.c",
    "examples/init.c",
    "examples/lg2.c",
    "examples/log.c",
    "examples/ls-files.c",
    "examples/ls-remote.c",
    "examples/merge.c",
    "examples/push.c",
    "examples/remote.c",
    "examples/rev-list.c",
    "examples/rev-parse.c",
    "examples/show-index.c",
    "examples/stash.c",
    "examples/status.c",
    "examples/tag.c",
};
