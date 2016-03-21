errors
======

[![GoDoc](https://godoc.org/github.com/vektra/errors?status.svg)](https://godoc.org/github.com/vektra/errors)
[![Build Status](https://travis-ci.org/vektra/errors.svg?branch=master)](https://travis-ci.org/vektra/errors)

This is a replacement package for the stdlib errors package.

It provides the same interface (which is really just the `New()` function) as
well as a number of functions and types for adding context to errors and
extracting that context information.

## Types

### Here

The `Here()` function wraps an error with information about the current code
location as the file:line. This allows later tools that print out the error
to show where the error bubbled up from.

### Cause

The `Cause()` function wraps 2 errors. The idea here is that when a lowlevel
error is detected, you wrap a highlevel error attached the lowlevel error, like
`Cause(New("something bad happened"), networkErr)`. This allows code
that prints things out to see what these highlevel errors were derived.

### Trace

The "Big Kahuna" of context types. Wraps an error with the stacktrace about the
current goroutine.

### Context

Allows for an error to be decorated with a string describing the context
of the error. This is intented to be used instead of using
`fmt.Errorf("while running wild: %s", err)` because it preserves the ability
check the original error.

### Subject

Allows a subject to be attached to an error. An example of this would be the
ability to indicate an error with a specific file path:
given `err = ErrNotFound`, `Subject(err, path)`. Similar to context, the idea
is the ability to attach additional information to the error without destroying
the ability to compare against it later.

## Functions

### Equal

Compares 2 errors smartly. It removes any wrappers defined in this package, allowing
for comparison against true base errors without the wrappers changing the ability
to detect them.

For instance, given a function that does `return Here(ErrNotExist)`, it's possible
to detect this specific error by doing `Equal(f(), ErrNotExist)`.

### Print

Use `Print()` to convert an error into a byte stream to be shown to the user. This
function understands the above types and shows their context information.

### Show

A convience for using `Print()` on `os.Stderr`

### Details

Creates a `map[string]string` with information about the error. This understands
the above types and adds the context information. This is very useful for sending
errors as structured text, such as json.

For example: `json.NewEncoder(rw).Encode(errors.Details(err))` to send an
errors as nicely formatted json over a `net.ResponseWritter`.

### EOF

This function seems a little out of place, but it fills an important niche. The
go stdlib does not collapse errors that represent a closed network connection
into `io.EOF`. As a result, detecting that a connection was closed requires
odd code at best. `EOF()` attempts to wrap this checking with platform specific
code to be able to detect lowlevel `syscall.Errno` type errors that represent
closure and indicate that they are in fact EOFs.

This function returns a boolean rather than collapsing to `io.EOF` to make it's
usage simple: `if errors.EOF(networkErr) { .... }`
