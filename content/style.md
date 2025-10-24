# Programming Style

# Programming and Research Style

My personal notes on programming style, research methodology, and technical
writing practices.

## Programming

### Code Clarity

- Write code as if the next person maintaining it is a violent psychopath who
  knows where you live
- Prefer explicit over implicit - make intentions clear
- Use descriptive variable names, avoid abbreviations except for well-known
  conventions
- Comment the "why", not the "what"

### Systems Programming

- Always check return values and handle errors appropriately
- Understand the cost of operations - memory allocations, system calls, etc.
- Write portable code when possible, but don't sacrifice clarity for portability
- Use the right tool for the job - sometimes assembly is necessary, sometimes
  high-level is better

## Research and Writing

### Paper Analysis

- Always read the paper multiple times - first for understanding, then for
  critical analysis
- Take notes on key contributions, methodology, and limitations
- Try to implement or at least understand the implementation details
- Connect new papers to previously studied work

### Technical Writing

- Start with a clear outline and stick to it
- Use examples and code snippets to illustrate concepts
- Explain complex ideas in simple terms
- Always provide context for why something is important

## Learning Approach

### Understanding Systems

- Start with the fundamentals - understand how things work at the lowest level
- Build up from basics - don't skip foundational concepts
- Experiment and break things - learn through hands-on exploration
- Read the source code - it's often the best documentation

*These are personal guidelines that evolve as I learn and grow as a programmer
and researcher.* context is named `params`.

: `params`

A bag of named arguments. Unlike `config`, might hold not only pod types.

: `config`

Generally user-specified POD parameters.

: `sink`

"output" of an internal iterator, typically `sink: &mut FnMut(T)` or
`sink: &mut Vec<T>`.

: `lhs`, `rhs`

operands of a binary operator.

: `fuel`

Recursion and infinite loop guards

: `result`

A "return" variable.

: `line_index`, `line_number`

Index is unambiguously zero-based. By convention, number is one-based.

Equisized pairs;

- add/sub, mul/div
- lhs/rhs
- s/e
- next/prev
- source/target
- src/dst
- index/count
- insert/remove
- beg/end
- fresh/stale
- prefix/suffix
- receive/consume
- internal/external

### Explicit Data Tables

Remove code duplication by extracting commonalities into tabular data

    // GOOD
    const cases = ["foo", "bar", "baz"];
    for case in cases {
        if x == case {

        }
    }

    // BAD
    if x == "foo" {

    } else if x == "bar" {

    } else if x == "baz" {

    }

### Bulk IO

Avoid opening file descriptors in favor of bulk operations. To write data to a
file, you need to follow a lifecycle: open file descriptor, issue write
syscalls, close file descriptor. Lifecycle handling requires complicated
type-system machinery and is better avoided. Usually, standard library provides
something like `std::fs::read_to_string` which encapsulates lifecycle
management.

## Rust

### No Self Types

Write types out explicitly, avoid `Self` alias if possible:

``` rust
// Good
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub text: String,
}

impl Diagnostic {
    pub fn new(code: DiagnosticCode, text: String) -> Diagnostic {
        Diagnostic { code, text }
    }
}

// Bad
impl Diagnostic {
    pub fn new(code: DiagnosticCode, text: String) -> Self {
        Self { code, text }
    }
}
```

*Rationale:* reducing cognitive load, optimizing for the reader. Resolving
`Self` is a small mental effort, it can be avoided.

### Prefer new Over default

Use `new` over `default` to construct instances.

*Rationale:* new is too ingrained.

### Blank Line Between Declarations

Leave blank line between top-level declarations:

``` rust
// Good
impl Foo {
    pub fn foo() {
    }

    pub fn bar() {
    }
}

// Bad
impl Foo {
    pub fn foo() {
    }
    pub fn bar() {
    }
}
```

*Rationale:* consistency. Omitting blank line leads to somewhat terser code, but
is very hard to do consistently.

### Derive Order

Use the following order of derives:

``` rust
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
```

*Rationale:* consistency. Debug comes last because it is the most often added
item.o
