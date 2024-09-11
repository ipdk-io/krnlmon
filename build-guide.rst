Krnlmon Build Guide
===================

Prerequisites
-------------

Install:

-  The Netlink library (libnl-3).

Build and install:

-  The target SDE (DPDK or ES2K). Krnlmon does not support Tofino.
-  The Stratum dependencies
   (`https://github.com/ipdk-io/stratum-deps <https://github.com/ipdk-io/stratum-deps>`__).

Environment Variables
---------------------

You can make things more convenient by defining the following
environment symbols:

-  ``DEP_INSTALL`` - directory path of the Stratum dependencies.
-  ``SDE_INSTALL`` - directory path of the target SDE.

Integrated Builds
-----------------

The kernel monitor is normally built in the top-level
(``networking-recipe``) folder as part of P4 Control Plane, and is
linked into the ``infrap4d`` executable.

You will generally want to begin by removing artifacts from previous
builds:

.. code:: text

   rm -fr build install

Note that these directories are specific to integrated builds. They have
no effect on standalone builds.

Integrated builds are usually done using the helper script
``make-all.sh``.

Full build
~~~~~~~~~~

To build all of P4 Control Plane, including the client programs:

.. code:: bash

   ./make-all.sh --target=TARGET --rpath

where TARGET is ``dpdk`` or ``es2k``.

Full build without OVS
~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   ./make-all.sh --target=TARGET --rpath --no-ovs

This removes the need for ``make-all.sh`` to build Open vSwitch and
enables/disables certain functionality in krnlmon.

Krnlmon only
~~~~~~~~~~~~

To build just krnlmon:

.. code:: bash

   ./make-all.sh --target-TARGET --rpath --no-build
   cmake --build build -j4 --target krnlmon

Standalone Builds
-----------------

It is possible to build krnlmon by itself, from within the
``krnlmon/krnlmon`` folder. This is useful when you are modifying the
krnlmon source code.

You will generally want to begin by removing artifacts from previous
builds:

.. code:: text

   rm -fr build install

Note that these directories are specific to standalone builds. The have
no effect on integrated builds.

DPDK CMake build
~~~~~~~~~~~~~~~~

.. code:: bash

   cmake -B build -C dpdk.cmake [options]
   cmake --build build -j4 --target install

``dpdk.cmake`` is a cmake configuration file that selects the DPDK
target, sets the install prefix to ``install``, and enables RPATH. The
SDE install path will taken from the ``SDE_INSTALL`` environment
variable, and the Stratum Dependencies install path will be taken from
the ``DEPS_INSTALL``

You may specify additional options, or override the configuration file,
by setting cmake variables (``-DVARNAME=VALUE``) on the command line.
You can unset a variable by specifying ``-UVARNAME``.

You can also create your own configuration file and use it in place of
``dpdk.cmake`` or ``es2k.cmake``.

ES2K CMake build
~~~~~~~~~~~~~~~~

.. code:: bash

   cmake -B build -C es2k.cmake [-DLNW_VERSION={2|3}] [options]
   cmake --build build -j4 --target install

The ``LNW_VERSION`` variable specifiess whether krnlmon should support
version 2 or 3 of the Linux Networking P4 program. The default is version 3.

DPDK Bazel build
~~~~~~~~~~~~~~~~

To build for DPDK using Bazel:

.. code:: bash

   bazel build --config dpdk //:krnlmon

To build without OVS:

.. code:: bash

   bazel build --config dpdk --//flags:ovs=no //:krnlmon

The ``--//flags`` parameter can also go at the end of the line, after
the ``//:krnlmon`` target label.

To build the dummy application:

.. code:: bash

   bazel build --config dpdk //:dummy_krnlmon

This allows you to check for unresolved external symbols in the krnlmon
library.

To check for RPATH issues:

.. code:: bash

   ldd bazel-bin/dummy_krnlmon

ES2K Bazel build
~~~~~~~~~~~~~~~~

To build for ES2K using Bazel, replace ``--config dpdk`` in the above
examples with ``--config es2k``.
