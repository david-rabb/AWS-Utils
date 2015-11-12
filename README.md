# AWS Java Utils
Various wrappers and utilities for using AWS in a Java web application.

## aws.http

#### AWSLoadBalancerFilter
A javax.servlet.Filter implementation to fold in the request headers sent by 
AWS Elastic Load Balancers so request scheme and remote address can be detected as they
were sent by the browser rather than what is being sent directly by the ELB.
More info here: http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html


## aws.crypto

#### AES
Simplified interface for AES encryption/decryption of text or streams. This implementation enforces the following specs:
* __Algorithm: AES 256__ - Symmetric Encryption with 256 bit keys
* __Scheme:	GCM__ - Authenticated Encryption with AAD, 128bit GCM tab bit length
* __IV Size:	16 bytes__
* __Text Encoding:	UTF-8__

#### KMS
Wrapper for using AWS KMS as a keystore to perform envelope encryption. Security benefits over a local keystore include:
* Master keys are not stored on local server
* Multiple clients can use the same keys
* Access keys to KMS can be revoked from AWS console
_Usage Notes_: 
* Data keys need to be generated in advance of usage and app deployment. 
* Recommended Role-Based access to production KMS keystores rather than user-based credentials.
