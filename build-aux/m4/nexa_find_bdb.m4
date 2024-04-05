dnl Copyright (c) 2013-2015 The Bitcoin Core developers
dnl Copyright (c) 2022 The Bitcoin Unlimited developers
dnl Distributed under the MIT software license, see the accompanying
dnl file COPYING or http://www.opensource.org/licenses/mit-license.php.

AC_DEFUN([BITCOIN_FIND_BDB],[
  AC_ARG_VAR([BDB_CFLAGS], [C compiler flags for BerkeleyDB, bypasses autodetection])
  AC_ARG_VAR([BDB_LIBS], [Linker flags for BerkeleyDB, bypasses autodetection])

  if test "x$BDB_CFLAGS" = "x"; then
    AC_MSG_CHECKING([for Berkeley DB C++ headers])
    BDB_CPPFLAGS=
    bdbpath=X
    bdbpathnot53=X
    bdbdirlist=
    for _vn in 5 5.3 ''; do
      for _pfx in b lib ''; do
        bdbdirlist="$bdbdirlist ${_pfx}db${_vn}"
      done
    done
    for searchpath in $bdbdirlist ''; do
      test -n "${searchpath}" && searchpath="${searchpath}/"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <${searchpath}db_cxx.h>
      ]],[[
        #if !(DB_VERSION_MAJOR == 5 && DB_VERSION_MINOR == 3)
          #error "failed to find bdb 5.3"
        #endif
      ]])],[
          bdbpath="${searchpath}"
      ],[])
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <${searchpath}db_cxx.h>
      ]],[[
        #if !( (DB_VERSION_MAJOR >= 4) || (DB_VERSION_MAJOR == 4 && DB_VERSION_MAJOR == 8) )
          #error "failed to find bdb 4.8+ other than 5.3"
        #endif
      ]])],[
        if test "x$bdbpathnot53" = "xX"; then
          bdbpathnot53="${searchpath}"
        fi
        continue
      ],[])
    done

    has_incompat_flag=no

    AC_ARG_WITH([incompatible-bdb],[AS_HELP_STRING([--with-incompatible-bdb], [allow using a bdb version other than 5.3])],[
      has_incompat_flag=yes
    ],[
      has_incompat_flag=no
    ])

    if test "x$has_incompat_flag" = xyes; then
        if test "x$bdbpathnot53" != "xX"; then
            AC_MSG_WARN([Found Berkeley DB other than 5.3; wallets opened by this build will not be portable!])
            bdbpath="${bdbpathnot53}"
            BITCOIN_SUBDIR_TO_INCLUDE(BDB_CPPFLAGS,[${bdbpath}],db_cxx)
        elif test "x$bdbpath" != "xX"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([Found Berkeley DB 5.3 but --with-incompatible-bdb flag was used; please remove the --with-incompatible dbd configure flag!])
        else
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([libdb_cxx headers missing, ]AC_PACKAGE_NAME[ requires this library version 5.3 for wallet functionality (--disable-wallet to disable wallet functionality)])
        fi
    else
        if test "x$bdbpath" != "xX"; then
            BITCOIN_SUBDIR_TO_INCLUDE(BDB_CPPFLAGS,[${bdbpath}],db_cxx)
        elif test "x$bdbpathnot53" != "xX"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([Found Berkeley DB other than 5.3, required for portable wallets (--with-incompatible-bdb to ignore or --disable-wallet to disable wallet functionality)])
        else
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([libdb_cxx headers missing, ]AC_PACKAGE_NAME[ requires this library version 5.3 for wallet functionality (--disable-wallet to disable wallet functionality)])
        fi
    fi
  else
    BDB_CPPFLAGS=${BDB_CFLAGS}
  fi
  AC_SUBST(BDB_CPPFLAGS)

  if test "x$BDB_LIBS" = "x"; then
    # TODO: Ideally this could find the library version and make sure it matches the headers being used
    for searchlib in db_cxx-5.3 db_cxx db5_cxx; do
      AC_CHECK_LIB([$searchlib],[main],[
        BDB_LIBS="-l${searchlib}"
        break
      ])
    done
    if test "x$BDB_LIBS" = "x"; then
        AC_MSG_ERROR([libdb_cxx missing, ]AC_PACKAGE_NAME[ requires this library version 5.3 or higher for wallet functionality (--disable-wallet to disable wallet functionality)])
    fi
  fi
  AC_SUBST(BDB_LIBS)
])
