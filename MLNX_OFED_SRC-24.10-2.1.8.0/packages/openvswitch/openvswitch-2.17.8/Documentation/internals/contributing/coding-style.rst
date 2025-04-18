..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============
Coding Style
============

This file describes the coding style used in most C files in the Open vSwitch
distribution. However, Linux kernel code datapath directory follows the Linux
kernel's established coding conventions. For the Windows kernel datapath code,
use the coding style described in :doc:`coding-style-windows`.

The following GNU indent options approximate this style.

::

    -npro -bad -bap -bbb -br -blf -brs -cdw -ce -fca -cli0 -npcs -i4 -l79 \
    -lc79 -nbfda -nut -saf -sai -saw -sbi4 -sc -sob -st -ncdb -pi4 -cs -bs \
    -di1 -lp -il0 -hnl

.. _basics:

Basics
------

- Limit lines to 100 characters.

- Use form feeds (control+L) to divide long source files into logical pieces. A
  form feed should appear as the only character on a line.

- Do not use tabs for indentation.

- Avoid trailing spaces on lines.

.. _naming:

Naming
------

- Use names that explain the purpose of a function or object.

- Use underscores to separate words in an identifier: ``multi_word_name``.

- Use lowercase for most names. Use uppercase for macros, macro parameters,
  and members of enumerations.

- Give arrays names that are plural.

- Pick a unique name prefix (ending with an underscore) for each
  module, and apply that prefix to all of that module's externally
  visible names. Names of macro parameters, struct and union members,
  and parameters in function prototypes are not considered externally
  visible for this purpose.

- Do not use names that begin with ``_``. If you need a name for "internal use
  only", use ``__`` as a suffix instead of a prefix.

- Avoid negative names: ``found`` is a better name than ``not_found``.

- In names, a ``size`` is a count of bytes, a ``length`` is a count of
  characters.  A buffer has size, but a string has length. The length of a
  string does not include the null terminator, but the size of the buffer that
  contains the string does.

.. _comments:

Comments
--------

Comments should be written as full sentences that start with a capital letter
and end with a period. Put two spaces between sentences.

Write block comments as shown below. You may put the ``/*`` and ``*/`` on the
same line as comment text if you prefer.

::

    /*
     * We redirect stderr to /dev/null because we often want to remove all
     * traffic control configuration on a port so its in a known state.  If
     * this done when there is no such configuration, tc complains, so we just
     * always ignore it.
     */

Each function and each variable declared outside a function, and each struct,
union, and typedef declaration should be preceded by a comment. See functions_
below for function comment guidelines.

Each struct and union member should each have an inline comment that explains
its meaning. structs and unions with many members should be additionally
divided into logical groups of members by block comments, e.g.:

::

    /* An event that will wake the following call to poll_block(). */
    struct poll_waiter {
        /* Set when the waiter is created. */
        struct ovs_list node;       /* Element in global waiters list. */
        int fd;                     /* File descriptor. */
        short int events;           /* Events to wait for (POLLIN, POLLOUT). */
        poll_fd_func *function;     /* Callback function, if any, or null. */
        void *aux;                  /* Argument to callback function. */
        struct backtrace *backtrace; /* Event that created waiter, or null. */

        /* Set only when poll_block() is called. */
        struct pollfd *pollfd;      /* Pointer to element of the pollfds array
                                       (null if added from a callback). */
    };

Use ``XXX`` or ``FIXME`` comments to mark code that needs work.

Don't use ``//`` comments.

Don't comment out or ``#if 0`` out code. Just remove it. The code that was
there will still be in version control history.

.. _functions:

Functions
---------

Put the return type, function name, and the braces that surround the function's
code on separate lines, all starting in column 0.

Before each function definition, write a comment that describes the function's
purpose, including each parameter, the return value, and side effects.
References to argument names should be given in single-quotes, e.g. ``'arg'``.
The comment should not include the function name, nor need it follow any formal
structure. The comment does not need to describe how a function does its work,
unless this information is needed to use the function correctly (this is often
better done with comments *inside* the function).

Simple static functions do not need a comment.

Within a file, non-static functions should come first, in the order that they
are declared in the header file, followed by static functions.  Static
functions should be in one or more separate pages (separated by form feed
characters) in logical groups. A commonly useful way to divide groups is by
"level", with high-level functions first, followed by groups of progressively
lower-level functions. This makes it easy for the program's reader to see the
top-down structure by reading from top to bottom.

All function declarations and definitions should include a prototype.  Empty
parentheses, e.g. ``int foo();``, do not include a prototype (they state that
the function's parameters are unknown); write ``void`` in parentheses instead,
e.g. ``int foo(void);``.

Prototypes for static functions should either all go at the top of the file,
separated into groups by blank lines, or they should appear at the top of each
page of functions. Don't comment individual prototypes, but a comment on each
group of prototypes is often appropriate.

In the absence of good reasons for another order, the following parameter order
is preferred. One notable exception is that data parameters and their
corresponding size parameters should be paired.

1. The primary object being manipulated, if any (equivalent to the ``this``
   pointer in C++).

2. Input-only parameters.

3. Input/output parameters.

4. Output-only parameters.

5. Status parameter.

Example:

::

    ```
    /* Stores the features supported by 'netdev' into each of '*current',
     * '*advertised', '*supported', and '*peer' that are non-null.  Each value
     * is a bitmap of "enum ofp_port_features" bits, in host byte order.
     * Returns 0 if successful, otherwise a positive errno value.  On failure,
     * all of the passed-in values are set to 0. */
    int
    netdev_get_features(struct netdev *netdev,
                        uint32_t *current, uint32_t *advertised,
                        uint32_t *supported, uint32_t *peer)
    {
        ...
    }
    ```

Functions that destroy an instance of a dynamically-allocated type should
accept and ignore a null pointer argument. Code that calls such a function
(including the C standard library function ``free()``) should omit a
null-pointer check. We find that this usually makes code easier to read.

Functions in ``.c`` files should not normally be marked ``inline``, because it
does not usually help code generation and it does suppress compiler warnings
about unused functions. (Functions defined in ``.h`` usually should be marked
``inline``.)

.. _function prototypes:

Function Prototypes
-------------------

Put the return type and function name on the same line in a function prototype:

::

    static const struct option_class *get_option_class(int code);

Omit parameter names from function prototypes when the names do not give useful
information, e.g.:

::

    int netdev_get_mtu(const struct netdev *, int *mtup);

Statements
----------

Indent each level of code with 4 spaces. Use BSD-style brace placement:

::

    if (a()) {
        b();
        d();
    }

Put a space between ``if``, ``while``, ``for``, etc. and the expressions that
follow them.

Enclose single statements in braces:

::

    if (a > b) {
        return a;
    } else {
        return b;
    }

Use comments and blank lines to divide long functions into logical groups of
statements.

Avoid assignments inside ``if`` and ``while`` conditions.

Do not put gratuitous parentheses around the expression in a return statement,
that is, write ``return 0;`` and not ``return(0);``

Write only one statement per line.

Indent ``switch`` statements like this:

::

    switch (conn->state) {
    case S_RECV:
        error = run_connection_input(conn);
        break;

    case S_PROCESS:
        error = 0;
        break;

    case S_SEND:
        error = run_connection_output(conn);
        break;

    default:
        OVS_NOT_REACHED();
    }

``switch`` statements with very short, uniform cases may use an abbreviated
style:

::

    switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    default: return "Unknown";
    }

Use ``for (;;)`` to write an infinite loop.

In an ``if/else`` construct where one branch is the "normal" or "common" case
and the other branch is the "uncommon" or "error" case, put the common case
after the ``if``, not the ``else``. This is a form of documentation. It also
places the most important code in sequential order without forcing the reader
to visually skip past less important details. (Some compilers also assume that
the ``if`` branch is the more common case, so this can be a real form of
optimization as well.)

Return Values
-------------

For functions that return a success or failure indication, prefer one of the
following return value conventions:

- An ``int`` where ``0`` indicates success and a positive errno value indicates
  a reason for failure.

- A ``bool`` where ``true`` indicates success and ``false`` indicates failure.

Macros
------

Don't define an object-like macro if an enum can be used instead.

Don't define a function-like macro if a ``static inline`` function can be used
instead.

If a macro's definition contains multiple statements, enclose them with
``do { ... } while (0)`` to allow them to work properly in all syntactic
circumstances.

Do use macros to eliminate the need to update different parts of a single file
in parallel, e.g. a list of enums and an array that gives the name of each
enum. For example:

::

    /* Logging importance levels. */
    #define VLOG_LEVELS                             \
        VLOG_LEVEL(EMER, LOG_ALERT)                 \
        VLOG_LEVEL(ERR, LOG_ERR)                    \
        VLOG_LEVEL(WARN, LOG_WARNING)               \
        VLOG_LEVEL(INFO, LOG_NOTICE)                \
        VLOG_LEVEL(DBG, LOG_DEBUG)
    enum vlog_level {
    #define VLOG_LEVEL(NAME, SYSLOG_LEVEL) VLL_##NAME,
        VLOG_LEVELS
    #undef VLOG_LEVEL
        VLL_N_LEVELS
    };

    /* Name for each logging level. */
    static const char *level_names[VLL_N_LEVELS] = {
    #define VLOG_LEVEL(NAME, SYSLOG_LEVEL) #NAME,
        VLOG_LEVELS
    #undef VLOG_LEVEL
    };

Thread Safety Annotations
-------------------------

Use the macros in ``lib/compiler.h`` to annotate locking requirements. For
example:

::

    static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
    static struct ovs_rwlock rwlock = OVS_RWLOCK_INITIALIZER;

    void function_require_plain_mutex(void) OVS_REQUIRES(mutex);
    void function_require_rwlock(void) OVS_REQ_RDLOCK(rwlock);

Pass lock objects, not their addresses, to the annotation macros. (Thus we have
``OVS_REQUIRES(mutex)`` above, not ``OVS_REQUIRES(&mutex)``.)

.. _source files:

Source Files
------------

Each source file should state its license in a comment at the very top,
followed by a comment explaining the purpose of the code that is in that file.
The comment should explain how the code in the file relates to code in other
files. The goal is to allow a programmer to quickly figure out where a given
module fits into the larger system.

The first non-comment line in a ``.c`` source file should be:

::

    #include <config.h>

``#include`` directives should appear in the following order:

1. ``#include <config.h>``

2. The module's own headers, if any. Including this before any other header
   (besides ) ensures that the module's header file is self-contained (see
   `header files`_ below).

3. Standard C library headers and other system headers, preferably in
   alphabetical order. (Occasionally one encounters a set of system headers
   that must be included in a particular order, in which case that order must
   take precedence.)

4. Open vSwitch headers, in alphabetical order. Use ``""``, not ``<>``, to
   specify Open vSwitch header names.

.. _header files:

Header Files
------------

Each header file should start with its license, as described under `source
files`_ above, followed by a "header guard" to make the header file idempotent,
like so:

::

    #ifndef NETDEV_H
    #define NETDEV_H 1

    ...

    #endif /* netdev.h */

Header files should be self-contained; that is, they should ``#include``
whatever additional headers are required, without requiring the client to
``#include`` them for it.

Don't define the members of a struct or union in a header file, unless client
code is actually intended to access them directly or if the definition is
otherwise actually needed (e.g. inline functions defined in the header need
them).

Similarly, don't ``#include`` a header file just for the declaration of a
struct or union tag (e.g. just for ``struct ;``). Just declare the tag
yourself.  This reduces the number of header file dependencies.

Types
-----

Use typedefs sparingly. Code is clearer if the actual type is visible at the
point of declaration. Do not, in general, declare a typedef for a ``struct``,
``union``, or ``enum``. Do not declare a typedef for a pointer type, because
this can be very confusing to the reader.

A function type is a good use for a typedef because it can clarify code.  The
type should be a function type, not a pointer-to-function type. That way, the
typedef name can be used to declare function prototypes. (It cannot be used for
function definitions, because that is explicitly prohibited by C89 and C99.)

You may assume that ``char`` is exactly 8 bits and that ``int`` and ``long``
are at least 32 bits.

Don't assume that ``long`` is big enough to hold a pointer. If you need to cast
a pointer to an integer, use ``intptr_t`` or ``uintptr_t`` from .

Use the ``int_t`` and ``uint_t`` types from for exact-width integer types. Use
the ``PRId``, ``PRIu``, and ``PRIx`` macros from for formatting them with
``printf()`` and related functions.

For compatibility with antique ``printf()`` implementations:

-  Instead of ``"%zu"``, use ``"%"PRIuSIZE``.

-  Instead of ``"%td"``, use ``"%"PRIdPTR``.

-  Instead of ``"%ju"``, use ``"%"PRIuMAX``.

Other variants exist for different radixes. For example, use ``"%"PRIxSIZE``
instead of ``"%zx"`` or ``"%x"`` instead of ``"%hhx"``.

Also, instead of ``"%hhd"``, use ``"%d"``. Be cautious substituting ``"%u"``,
``"%x"``, and ``"%o"`` for the corresponding versions with ``"hh"``: cast the
argument to unsigned char if necessary, because ``printf("%hhu", -1)`` prints
``255`` but ``printf("%u", -1)`` prints ``4294967295``.

Use bit-fields sparingly. Do not use bit-fields for layout of network
protocol fields or in other circumstances where the exact format is
important.

Declare bit-fields to be signed or unsigned integer types or ``_Bool`` (aka
``bool``). Do *not* declare bit-fields of type ``int``: C99 allows these to be
either signed or unsigned according to the compiler's whim. (A 1-bit bit-field
of type ``int`` may have a range of ``-1...0``!)

Try to order structure members such that they pack well on a system with 2-byte
``short``, 4-byte ``int``, and 4- or 8-byte ``long`` and pointer types.  Prefer
clear organization over size optimization unless you are convinced there is a
size or speed benefit.

Pointer declarators bind to the variable name, not the type name. Write
``int *x``, not ``int* x`` and definitely not ``int * x``.

Expressions
-----------

Put one space on each side of infix binary and ternary operators:

::

    * / %
    + -
    << >>
    < <= > >=
    == !=
    &
    ^
    |
    &&
    ||
    ?:
    = += -= *= /= %= &= ^= |= <<= >>=

Avoid comma operators.

Do not put any white space around postfix, prefix, or grouping operators:

::

    () [] -> .
    ! ~ ++ -- + - * &

Exception 1: Put a space after (but not before) the "sizeof" keyword.

Exception 2: Put a space between the ``()`` used in a cast and the expression
whose type is cast: ``(void *) 0``.

Break long lines before the ternary operators ``?`` and ``:``, rather than
after them, e.g.

::

    return (out_port != VIGP_CONTROL_PATH
            ? alpheus_output_port(dp, skb, out_port)
            : alpheus_output_control(dp, skb, fwd_save_skb(skb),
                                     VIGR_ACTION));

Parenthesize the operands of ``&&`` and ``||`` if operator precedence makes it
necessary, or if the operands are themselves expressions that use ``&&`` and
``||``, but not otherwise. Thus::

    if (rule && (!best || rule->priority > best->priority)) {
        best = rule;
    }

but::

    if (!isdigit((unsigned char)s[0]) ||
        !isdigit((unsigned char)s[1]) ||
        !isdigit((unsigned char)s[2])) {
        printf("string %s does not start with 3-digit code\n", s);
    }

Do parenthesize a subexpression that must be split across more than one line,
e.g.::

    *idxp = ((l1_idx << PORT_ARRAY_L1_SHIFT) |
             (l2_idx << PORT_ARRAY_L2_SHIFT) |
             (l3_idx << PORT_ARRAY_L3_SHIFT));

Breaking a long line after a binary operator gives its operands a more
consistent look, since each operand has the same horizontal position.  This
makes the end-of-line position a good choice when the operands naturally
resemble each other, as in the previous two examples.  On the other hand,
breaking before a binary operator better draws the eye to the operator, which
can help clarify code by making it more obvious what's happening, such as in
the following example::

    if (!ctx.freezing
        && xbridge->has_in_band
        && in_band_must_output_to_local_port(flow)
        && !actions_output_to_local_port(&ctx)) {

Thus, decide whether to break before or after a binary operator separately in
each situation, based on which of these factors appear to be more important.

Try to avoid casts. Don't cast the return value of malloc().

The ``sizeof`` operator is unique among C operators in that it accepts two very
different kinds of operands: an expression or a type. In general, prefer to
specify an expression, e.g. ``int *x = xmalloc(sizeof *x);``. When the
operand of ``sizeof`` is an expression, there is no need to parenthesize that
operand, and please don't.

Use the ``ARRAY_SIZE`` macro from ``lib/util.h`` to calculate the number of
elements in an array.

When using a relational operator like ``<`` or ``==``, put an expression or
variable argument on the left and a constant argument on the right, e.g.
``x == 0``, *not* ``0 == x``.

Blank Lines
-----------

Put one blank line between top-level definitions of functions and global
variables.

C DIALECT
---------

Most C99 features are OK because they are widely implemented:

- Flexible array members (e.g. ``struct { int foo[]; }``).

- ``static inline`` functions (but no other forms of ``inline``, for which GCC
  and C99 have differing interpretations).

- ``long long``

- ``bool`` and ``<stdbool.h>``, but don't assume that ``bool`` or ``_Bool`` can
  only take on the values ``0`` or ``1``, because this behavior can't be
  simulated on C89 compilers.

  Also, don't assume that a conversion to ``bool`` or ``_Bool`` follows C99
  semantics, i.e. use ``(bool) (some_value != 0)`` rather than
  ``(bool) some_value``. The latter might produce unexpected results on non-C99
  environments. For example, if ``bool`` is implemented as a typedef of char
  and ``some_value = 0x10000000``.

- Designated initializers (e.g. ``struct foo foo = { .a = 1 };`` and
  ``int a[] = { [2] = 5 };``).

- Mixing of declarations and code within a block.  Favor positioning that
  allows variables to be initialized at their point of declaration.

- Use of declarations in iteration statements
  (e.g. ``for (int i = 0; i < 10; i++)``).

- Use of a trailing comma in an enum declaration (e.g.
  ``enum { x = 1, };``).

As a matter of style, avoid ``//`` comments.

Avoid using GCC or Clang extensions unless you also add a fallback for other
compilers. You can, however, use C99 features or GCC extensions also supported
by Clang in code that compiles only on GNU/Linux (such as
``lib/netdev-linux.c``), because GCC is the system compiler there.

Python
------

When introducing new Python code, try to follow Python's `PEP 8
<https://www.python.org/dev/peps/pep-0008/>`__ style. Consider running the
``pep8`` or ``flake8`` tool against your code to find issues.

Libraries
---------

When introducing a new library, follow
:doc:`Open vSwitch Library ABI guide <libopenvswitch-abi>`
