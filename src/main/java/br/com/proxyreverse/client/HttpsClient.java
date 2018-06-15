package br.com.proxyreverse.client;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cryptacular.util.CertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.proxyreverse.manager.KeyStoreManager;

@WebServlet(urlPatterns = "")
public class HttpsClient extends HttpServlet {

	private static final Logger logger = LoggerFactory.getLogger(HttpsClient.class);
	private static final long serialVersionUID = 6644332178282070109L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String path = request.getParameter("path");
		makeConnectionAndValidate(request.getRequestURL().toString(), response, path);
	}

	public void makeConnectionAndValidate(String path, HttpServletResponse response, String caminho) throws IOException {
		HttpsURLConnection connection = null;
		List<String> listAlias = new ArrayList<String>();

		try {
			URL url = new URL(caminho);
			connection = (HttpsURLConnection) url.openConnection();

			SSLSocketFactory sslSocketFactory = getFactory();
			connection.setSSLSocketFactory(sslSocketFactory);
			
			connection.connect();
			
			Certificate[] serverCertificate = connection.getServerCertificates();

			if (serverCertificate.length == 0) {
				logger.info("Nenhum certificado encontrado.");
			}

			for (Certificate certificate : serverCertificate) {

				if (certificate instanceof X509Certificate) {
					X509Certificate x509cert = (X509Certificate) certificate;
					listAlias.add(CertUtil.subjectCN(x509cert));
				}

			}

			X509Certificate cert = KeyStoreManager.verifyCertificate(listAlias);

			response.sendRedirect("https://www.google.com");
			connection.disconnect();

		} catch (ClassCastException e) {
			logger.error("permito apenas requests https.");
		} catch (Exception e) {
			if (connection != null) {
				connection.disconnect();
			}
			logger.error(e.getMessage());
		}
	}

	private static SSLSocketFactory getFactory() throws Exception {
		SSLContext context = SSLContext.getInstance("SSL");
		context.init(null, null, null);
		return context.getSocketFactory();
	}

}
