# Developer documentation

## Building

The SDK is built using Gradle:

```bash
./gradlew clean build
```

## Releasing

Currently a release of the SDK is triggered manually:

1. Make sure all changes to be included in the release have been merged into the `master` branch.
1. Bump the version in `build.gradle`, update the CHANGELOG, and make a new commit with those changes.
1. Push the commit to GitHub.
1. Create a [new release in GitHub](https://github.com/schibsted/account-sdk-java/releases/new), specifying
   the same version as in `build.gradle` as "tag version". Also make sure to include the updated text from the
   CHANGELOG in the release description.
1. When the tag is created it will trigger Travis to run all tests, build the new artifacts and publish them to
   Artifactory, as well as updating the published JavaDocs. 
