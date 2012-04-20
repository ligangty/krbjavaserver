package com.redhat.tools.kerberos;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Servlet implementation class KerberosServlet
 * 
 * @author ligangty@gmail.com
 */
public class KerberosServlet extends HttpServlet {

	private static final long serialVersionUID = -5112952138448116345L;

	private static final Log logger = LogFactory.getLog(KerberosServlet.class);

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public KerberosServlet() {
		super();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	protected void processRequest(HttpServletRequest req,
			HttpServletResponse res) throws IOException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		String header = request.getHeader("Authorization");

		if ((header != null) && header.startsWith("Negotiate ")) {
			if (logger.isDebugEnabled()) {
				logger.debug("Received Negotiate Header for request "
						+ request.getRequestURL() + ": " + header);
			}
			System.out.println(header);
			byte[] base64Token = header.substring(10).getBytes("UTF-8");
			System.out.println("key not decode by Base64:" + new String(base64Token));
			byte[] kerberosTicket = Base64.decode(base64Token);
			System.out.println("key decode by Base64:" + new String(kerberosTicket));

			SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
			String username = validator.validateTicket(kerberosTicket);
			
			request.setAttribute("username", username);
			
			response.getWriter().write("you are authenticated!your principle is:"+username);

			System.out.println(username);
		} else {
			response.addHeader("WWW-Authenticate", "Negotiate");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.flushBuffer();
		}

	}

}
