#!/bin/sh

# Create or update file with git version
#
# Tries not to update the file if nothing changed in order to
# avoid re-compiling the file that includes it.
#
# If for some reason this is not desirable, simply add -DMOD_MD_GITVERSION_H to CPPFLAGS.
# In that case, or when a build is not in a git repository, MD_GIT_VERSION will be undefined.

FILE="md_git_version.h"
rm -f  ${FILE}.new

in_repo=
if [ -d .git ] || [ -d ../.git ]; then
    in_repo="yes"
fi
if test x"$in_repo" = "xyes" &&  command -v git >/dev/null 2>&1; then
    echo "#ifndef MOD_MD_GITVERSION_H"                                                  >${FILE}.new
    echo "#define MOD_MD_GITVERSION_H"                                                 >>${FILE}.new
    echo "/* This build was in a git repository.  The version string consists"         >>${FILE}.new
    echo " * of the last tag on the checked-out branch, \"-\", the number of"          >>${FILE}.new
    echo " * commits since that tag, \"-g\" commit hash.  If there were unstaged"      >>${FILE}.new
    echo " * changes the final character will be \"+\". e.g. \"v2.3.1-22-g27098cc7+\"" >>${FILE}.new
    echo " *"                                                                          >>${FILE}.new
    echo " * Note that the last tag may not be the same as the MOD_MD_VERSION_NUM,"    >>${FILE}.new
    echo " * which is manually entered in configure.ac.  For more detail, see"         >>${FILE}.new
    echo " * \"git describe\""                                                         >>${FILE}.new
    echo " *"                                                                          >>${FILE}.new
    echo " * If a build is not in a repository, this file will be empty."              >>${FILE}.new
    echo " */"                                                                         >>${FILE}.new
    echo "#define MD_GIT_VERSION \"`git describe --abbrev=8 --dirty=+ --always --tags --first-parent`\"" >>${FILE}.new
    echo "#endif"                                                                      >>${FILE}.new
    if [ -f ${FILE} ] && diff -q ${FILE}.new ${FILE} >/dev/null 2>&1; then
        rm -f ${FILE}.new
    else
        rm -f ${FILE}
        mv ${FILE}.new ${FILE}
    fi
else
    if [ -s ${FILE} ] || ! [ -f ${FILE} ]; then
        # Guarantee that the file is empty with a new timestamp,
        cat </dev/null >${FILE};
    fi
fi

exit 0
