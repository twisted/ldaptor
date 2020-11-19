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

The recommended local dev enviroment is `tox -e py38-test-dev`

When running on local dev env, you will get a coverage report for whole
code as well as for the changes since `master`.
The reports are also produced in HTML at:

* build/coverage-html/index.html
* build/coverage-diff.html

You can run a subset of the test by passing the dotted path to the test or
test case, test module or test package::

    tox -e py38-test-dev ldaptor.test.test_delta.TestModifyOp.testAsLDIF
    tox -e py38-test-dev ldaptor.test.test_usage


Release notes
-------------

To simplify the release process each change should be recorded into the
docs/source/NEWS.rst in a wording targeted to end users.
Try not to write the release notes as a commit message.


Release process
---------------

The release is done automatically via GitHub actions when a new tag
is pushed. A new tag can be pushed with::

    pipx run --spec="zest.releaser[recommended]>=6.22.1" fullrelease

You can also run the zest.releaser process manually:

1. pick a new version number!
2. update the latest version and release date in ``docs/source/NEWS.rst``.
3. update the ``__version__ = "{version}"`` in ``ldaptor/__init__.py``.
4. tag the new release ``git tag v{version} -m 'Tagging {version}'``
5. apply steps 2. through 3. for the development release version.

PyPI access is done via the HTTP API token stored in GitHub Secrets as
PYPI_GITHUB_PACKAGE_UPLOAD from
https://github.com/twisted/ldaptor/settings/secrets

You can test the release process (without the publish) using `tox -e release`.
Inspect the distributable files with `tree dist`, you could upload them with `twine`.


Building the documentation
--------------------------

The documentation is managed using Python Sphinx and is generated in
build/docs.

There is a helper to build the documentation using tox ::

    tox -e documentation
