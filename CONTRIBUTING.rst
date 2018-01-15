How to Contribute
=================

Head over to: https://github.com/twisted/ldaptor and submit your bugs or
feature requests.

If you wish to contribute code, just fork it,
make a branch and send us a pull request.
We'll review it, and push back if necessary.

Check docs/PULL_REQUEST_TEMPLATE.md for more info about how to pull request
process.

Ldaptor generally follows the coding and documentation standards of the Twisted
project.


Development environment
-----------------------

Tox is used to manage both local development and CI environment.

The recommended local dev enviroment is `tox -e py27-test-dev`

When running on local dev env, you will get a coverage report for whole
code as well as for the changes since `master`.
The reports are also produced in HTML at:

* build/coverage-html/index.html
* build/coverage-diff.html

You can run a subset of the test by passing the dotted path to the test or
test case, test module or test package::

    tox -e py27-test-dev ldaptor.test.test_delta.TestModifyOp.testAsLDIF
    tox -e py27-test-dev ldaptor.test.test_usage


Release notes
-------------

To simplify the release process each change should be recorded into the
docs/source/NEWS.rst in a wording targeted to end users.
Try not to write the release notes as a commit message.


Building the documentation
--------------------------

The documentation is managed using Python Sphinx and is generated in
docs/build.

There is a helper to build the documentation using tox ::

    tox -e documentation
