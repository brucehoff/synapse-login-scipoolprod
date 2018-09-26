
package oauthUserInfo;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;


public class Auth extends HttpServlet {
	private static Logger logger = Logger.getLogger("Auth");

    private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%s&redirect_uri=%s";
    private static final String TOKEN_URL = "https://accounts.google.com/o/oauth2/token";

	private static final String GOOGLE_OAUTH_USER_INFO_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";

	public static final String EMAIL = "email";
	public static final String VERIFIED_EMAIL = "verified_email";
	public static final String ID = "id";
	public static final String GIVEN_NAME = "given_name";
	public static final String FAMILY_NAME = "family_name";
	
	private static final String SCOPE_EMAIL = "email";

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doPostIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			throw new RuntimeException(e);
		}
	}
	
	private static final String URI_ROOT = ""; // was /oauthUserInfo-1.0
	
	private String getRedirectBackUrl(HttpServletRequest req) throws MalformedURLException {
		String result = (new URL(req.getScheme(), req.getServerName(), req.getServerPort(), URI_ROOT+"/oauthUserInfo")).toString();
		logger.log(Level.INFO, "server-name="+req.getServerName());
		logger.log(Level.INFO, "redir url="+result);
		return result;
	}
	
	private static String getClientId() {
		String result = getProperty("OAUTH_CLIENT_ID");
		logger.log(Level.INFO, "OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecret() {
		String result =  getProperty("OAUTH_CLIENT_SECRET");
		logger.log(Level.INFO, "OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private void doPostIntern(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
				String redirectBackUrl = getRedirectBackUrl(req);
				String redirectUrl = new OAuth2Api(AUTHORIZE_URL, TOKEN_URL).
						getAuthorizationUrl(new OAuthConfig(getClientId(), null, redirectBackUrl, null, SCOPE_EMAIL, null));
				resp.setHeader("Location", redirectUrl);
				resp.setStatus(307);
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			throw new RuntimeException(e);
		}
	}
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws Exception {
		
		OAuthService service = (new OAuth2Api(AUTHORIZE_URL, TOKEN_URL)).
				createService(new OAuthConfig(getClientId(), getClientSecret(), getRedirectBackUrl(req), null, null, null));
		String authorizationCode = req.getParameter("code");
		Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
		// Use the access token to get the UserInfo from Google.
		OAuthRequest request = new OAuthRequest(Verb.GET, GOOGLE_OAUTH_USER_INFO_API_URL);
		service.signRequest(accessToken, request);
		Response response = request.send();
		if(!response.isSuccessful()){
			throw new Exception("Response code: "+response.getCode()+"Message: "+response.getMessage());
		}
		
		resp.setContentType("text/plain");
		resp.getOutputStream().println(response.getBody());
		resp.setStatus(200);
	}
	
	
	private static Properties properties = null;

	public static void initProperties() {
		if (properties!=null) return;
		properties = new Properties();
		InputStream is = null;
		try {
			is = Auth.class.getClassLoader().getResourceAsStream("global.properties");
			properties.load(is);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (is!=null) try {
				is.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static String getProperty(String key) {
		return getProperty(key, true);
	}
	
	private static boolean missing(String s) {
		return StringUtils.isEmpty(s) || "null".equals(s);
	}

	public static String getProperty(String key, boolean required) {
		initProperties();
		{
			String embeddedProperty = properties.getProperty(key);
			if (!missing(embeddedProperty)) return embeddedProperty;
		}
		{
			String environmentVariable = System.getenv(key);
			if (!missing(environmentVariable)) return environmentVariable;
		}
		{
			String commandlineOption = System.getProperty(key);
			if (!missing(commandlineOption)) return commandlineOption;
		}
		if (required) throw new RuntimeException("Cannot find value for "+key);
		return null;
	}

}
