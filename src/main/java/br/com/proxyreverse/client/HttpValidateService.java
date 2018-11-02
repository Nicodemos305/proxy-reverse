package br.com.proxyreverse.client;

import java.io.IOException;
import java.io.PrintWriter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.validator.routines.UrlValidator;
import org.springframework.stereotype.Service;

@Service
public class HttpValidateService {

	public SSLSocketFactory getFactory() throws Exception {
		SSLContext context = SSLContext.getInstance("SSL");
		context.init(null, null, null);
		return context.getSocketFactory();
	}

	public Boolean invalidUrl(String url) {

		String[] schemes = { "https" };
		UrlValidator urlValidator = new UrlValidator(schemes);

		if (urlValidator.isValid(url)) {
			return false;
		} else {
			return true;
		}

	}

	public void redirectToServer(String serverName, HttpServletResponse response) {
		try {
			response.sendRedirect("https://" + serverName);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void makeMessageError(Integer status, HttpServletResponse response, PrintWriter print, String mensagem) {
		response.setStatus(status);
		print.println(mensagem);
		print.close();

	}

	public Boolean validatePath(String path, HttpServletResponse response, PrintWriter writer) {

		if (path == null || path.isEmpty()) {
			makeMessageError(400, response, writer, "O parametro é obrigatorio.");
			return false;
		}

		if (invalidUrl(path)) {
			makeMessageError(400, response, writer, "Problema na url(Somente são aceitos request https).");
			return false;
		}

		return true;
	}
}
