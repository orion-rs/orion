
### 1. What to contribute
There are a variety of things that one may contribute to this project. Contributions of any kind are always welcomed.

#### 1.1 Features and Improvements
Improvements to the library can come in many flavors: performance, security, usability, etc.
An improvement that doesn't add new features or are breaking changes, may be submitted as pull requests directly.

Features that add new functionality or are breaking changes should preferably be discussed in a separate issue first.

See [Rust API Guidelines](https://rust-lang-nursery.github.io/api-guidelines/checklist.html) and [Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/) for some checklists on how to implement new features.

#### 1.2 Testing
One way to contribute to testing is by writing new unit-tests to cover code that isn't already being tested. Improvements to existing unit-tests is also an option.

Adding test vectors (located in `/tests`) is also a good way to improve the testing of the library. Test vectors can be official or generated using another crypto library.

#### 1.3 Fuzzing
Fuzzing is an important part of testing this library. Contributions to this aspect can come in two ways: 1) Running the fuzzing targets, updating the corpus and reporting any issues found and 2) Overall improvements to the fuzzing targets.

Please refer to the [orion-fuzz](https://github.com/brycx/orion-fuzz) repository when working with fuzzing.

#### 1.4 Documentation
Quality of documentation is a vital part of this project. Contributions to this could include adding documentation where such is missing, clarifying documentation that is unclear or improving examples.

Try to make changes adhere to the [Rust API Guidelines](https://rust-lang-nursery.github.io/api-guidelines/checklist.html) as much as possible.

### 2. Bug Reports
A bug report should _ideally_ include all the information in this template:

```
Brief description:

Steps to reproduce:

Expected result:

Actual result:

Additional information:
    - Rust version ($ rustc -V)
    - orion version
```

Bug reports don't need to strictly follow this template but in most cases, more information about the bug makes it easier to analyze and fix.

### 3. Pull Requests

Before submitting a pull request, please make sure you have done the following:

- [ ] A change or addition of functionality is covered by unit-tests.

- [ ] Ensure that all tests pass when running:
  
  - `cargo test`
  - `cargo +nightly test --tests --no-default-features`

- [ ] The formatting is correct and clippy does not show warnings by running:

  - `cargo clippy`
  - `cargo fmt`

- [ ] Explain what the pull request changes, in the description of the GitHub PR.
- [ ] If the pull request is a bugfix, try to include a regression test for the bug.

All pull requests should be opened against the `master` branch.

If your pull request is still work-in-progress, make the title of the pull request start with `[WIP]`.

### 4. Feature Requests
A request for a new feature should be started in a GitHub issue. This issue should explain what feature is requested, why it is requested and, if applicable, the use-case behind it.