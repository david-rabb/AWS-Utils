# AWS Java Utils
Various wrappers and utilities for using AWS in a Java web application.

## aws.http
### AWSLoadBalancerFilter
A javax.servlet.Filter implementation to fold in the request headers sent by 
AWS Elastic Load Balancers so request scheme and remote address can be detected as they
were sent by the browser rather than what is being sent directly by the ELB.
More info here: http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html


