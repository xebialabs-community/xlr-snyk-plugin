# XL Release Snyk plugin v1.0.0

[![Build Status][xlr-snyk-plugin-travis-image]][xlr-snyk-plugin-travis-url]
[![License: MIT][xlr-snyk-plugin-license-image]][xlr-snyk-plugin-license-url]

[xlr-snyk-plugin-travis-image]: https://travis-ci.org/xebialabs-community/xlr-snyk-plugin.svg?branch=master
[xlr-snyk-plugin-travis-url]: https://travis-ci.org/xebialabs-community/xlr-snyk-plugin
[xlr-snyk-plugin-license-image]: https://img.shields.io/badge/License-MIT-yellow.svg
[xlr-snyk-plugin-license-url]: https://opensource.org/licenses/MIT
[xlr-snyk-plugin-downloads-image]: https://img.shields.io/github/downloads/xebialabs-community/xlr-snyk-plugin/total.svg

#### IMPORTANT ####

* A Snyk Organization with API access will need to be setup with Snyk.io <https://snyk.io/>


## Preface

This document describes the functionality provided by the XL Release (XLR) Snyk plugin.

See the [XL Release reference manual](https://docs.xebialabs.com/xl-release) for background information on XL Release and release automation concepts.  

## Overview
The Snyk plugin for XLR will interact with Snyk's API to determine the status of a project based on Snyk scans.  Issue severities can be used to determine the project's viability to be included in the release.  The XLR Task has the ability to react to the three Snyk severity levels (High, Medium, Low)

## Requirements

Note:  XLR version should not be lower than lowest supported version.  See <https://support.xebialabs.com/hc/en-us/articles/115003299946-Supported-XebiaLabs-product-versions>.

* Snyk Orginazation ID (setup via Snyk.io web portal)
* One or more Projects setup with Snyk with a completed scan (setup via Snyk.io web portal)
* Snyk API Token (setup via Snyk.io web portal)
* One or more Snyk Project ID's (used by XLR Task - one per Task)

## Installation

* Copy the latest JAR file from the [releases page](https://github.com/xebialabs-community/xlr-snyk-plugin/releases) into the `RELEASE_SERVER/plugins` directory.
* Restart the XL Release server.

## Usage/Tasks

Once the Snyk plugin is installed, a Snyk Server Configuration can be created to define:
* The API Base URL: https://snyk.io/api/v1
* The Snyk Auth TOKEN: 01234567-89ab-cdef-0123-456789abcdef (setup via Snyk.io web portal)

With the Snyk Server Configuration defined, the Snyk Task can be setup inside a XLR Template to define:
* Snyk Server (defined previously)
* Organization ID (referenced from Snyk web portal)
* Project ID (referenced from Snyk web portal)
* Severity Level - this is the lowest severity level the Release can tollerate to allow the project to be included in the Release
* Halt on Issues is a check box to allow for a project to not cause a Release failure - default should be checked.

XLR Variables can be defined in XLR to allow passing project issue data along to a secondary XLR Task for evaluation
* High (as defined by Snyk Scan)
* Medium (as defined by Snyk Scan)
* Low (as defined by Snyk Scan)

## References

