package drx.aws.http;

/**
 * Title: AWSLoadBalancerFilter
 * Description: A javax.servlet.Filter implementation to fold in the request headers sent by 
 *   AWS Elastic Load Balancers so request scheme and remote address can be detected as they
 *   were sent by the browser rather than what is being sent directly by the ELB.
 *   More info here: http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html
 * @author David Rabb
 * @version 1.0
 */
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class AWSLoadBalancerFilter implements Filter {

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    AWSWrapperRequest wrappedRequest = new AWSWrapperRequest((HttpServletRequest)request);
    chain.doFilter(wrappedRequest, response);
  }

  @Override
  public void destroy() {
  }
  
}

class AWSWrapperRequest extends HttpServletRequestWrapper  {
  HttpServletRequest request;

  public AWSWrapperRequest(HttpServletRequest request) {
    super(request);
    this.request = request;
  }

  /* Use the scheme as seen by ELB rather than the how the ELB connects to this app server */
  @Override
  public String getScheme() {
    String forwardedProtocol = request.getHeader("x-forwarded-proto");
    if (forwardedProtocol!=null && forwardedProtocol.equalsIgnoreCase("https")) return "https";
    return request.getScheme();
  }

  /* Returns true if the connection to the ELB was secure. 
   * Connection between ELB and app server may or may not be secured depending on project requirements.
   */
  @Override
  public boolean isSecure() {
    return this.getScheme().equals("https");
  }

  /* Get last IP address in comma-separated list of proxied addresses. Only trust the last one
   * because a client could send it's own unverified x-forwarded-for header.
   */
  @Override
  public String getRemoteAddr() {
    String forwardedAddr = request.getHeader("x-forwarded-for");
    if (forwardedAddr!=null) {
      // AWS proxy just appends client IP to existing x-forward-for header
      int index = forwardedAddr.lastIndexOf(", ");
      if (index>0) {
        forwardedAddr = forwardedAddr.substring(index+2);
      }
      return forwardedAddr;
    }
    return request.getRemoteAddr();
  }

  /* Force host lookups to be ignored and return address */
  @Override
  public String getRemoteHost() {
    return this.getRemoteAddr();
  }


}