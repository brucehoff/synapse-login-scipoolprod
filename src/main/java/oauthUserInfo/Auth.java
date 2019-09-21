
package oauthUserInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletOutputStream;
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

    private static final String AUTHORIZE_URL_SYNAPSE = 
    		"https://staging-signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&"+
    "claims={\"id_token\":{\"team\":{\"values\":[\"3329051\"]},\"family_name\":{\"essential\":true},\"given_name\":{\"essential\":true},\"email\":{\"essential\":true},\"company\":{\"essential\":false}},\"userinfo\":{\"team\":{\"values\":[\"3329051\"]},\"family_name\":{\"essential\":true},\"given_name\":{\"essential\":true},\"email\":{\"essential\":true},\"company\":{\"essential\":false}}}";
    private static final String TOKEN_URL_SYNAPSE = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/token";

    private static final String AUTHORIZE_URL_GOOGLE = "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%s&redirect_uri=%s";
    private static final String TOKEN_URL_GOOGLE = "https://accounts.google.com/o/oauth2/token";

	private static final String AUTHORIZE_URL_ORCID = "https://orcid.org/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s";
	private static final String TOKEN_URL_ORCID = "https://pub.orcid.org/oauth/token";

	private static final String SYNAPSE_OAUTH_USER_INFO_API_URL = "https://repo-staging.prod.sagebase.org/auth/v1/oauth2/userinfo";
	private static final String GOOGLE_OAUTH_USER_INFO_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
	private static final String ORCID_OAUTH_USER_INFO_API_URL = "https://orcid.org/oauth/userinfo";
	
	private static final String SCOPE_EMAIL = "email";

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doPostIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("Error:");
				e.printStackTrace(new PrintStream(os));
			}
			resp.setStatus(500);
		}
	}

	private static final String CLIENT_ENDPOINT = "http://oauthuserinfo.appspot.com/";
	private static final String SYNAPSE_BUTTON_URI = "oauthUserInfoSynapse";
	private static final String GOOGLE_BUTTON_URI = "oauthUserInfoGoogle";
	private static final String ORCID_BUTTON_URI = "oauthUserInfoOrcid";
	
	private String getRedirectBackUrlGoogle(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+GOOGLE_BUTTON_URI;
	}
	
	private String getRedirectBackUrlSynapse(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+SYNAPSE_BUTTON_URI;
	}
	
	private String getRedirectBackUrlOrcid(HttpServletRequest req) throws MalformedURLException {
		return CLIENT_ENDPOINT+ORCID_BUTTON_URI;
	}
	
	private static String getClientIdSynapse() {
		String result = getProperty("SYNAPSE_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "SYNAPSE_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretSynapse() {
		String result =  getProperty("SYNAPSE_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "SYNAPSE_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private static String getClientIdGoogle() {
		String result = getProperty("GOOGLE_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "GOOGLE_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretGoogle() {
		String result =  getProperty("GOOGLE_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "GOOGLE_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private static String getClientIdOrcid() {
		String result = getProperty("ORCID_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "ORCID_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private static String getClientSecretOrcid() {
		String result =  getProperty("ORCID_OAUTH_CLIENT_SECRET");
		logger.log(Level.WARNING, "ORCID_OAUTH_CLIENT_SECRET="+result);
		return result;
	}
	
	private void doPostIntern(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		if (req.getRequestURI().contains(GOOGLE_BUTTON_URI)) {
			String redirectBackUrl = getRedirectBackUrlGoogle(req);
			String redirectUrl = new OAuth2Api(AUTHORIZE_URL_GOOGLE, TOKEN_URL_GOOGLE).
					getAuthorizationUrl(new OAuthConfig(getClientIdGoogle(), null, redirectBackUrl, null, SCOPE_EMAIL, null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(307);
		} else if (req.getRequestURI().contains(ORCID_BUTTON_URI)) {
			String redirectBackUrl = getRedirectBackUrlOrcid(req);
			String redirectUrl = new OAuth2Api(AUTHORIZE_URL_ORCID, TOKEN_URL_ORCID).
					getAuthorizationUrl(new OAuthConfig(getClientIdOrcid(), null, redirectBackUrl, null, "openid", null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(303);
		} else if (req.getRequestURI().contains(SYNAPSE_BUTTON_URI)) {
			String redirectBackUrl = getRedirectBackUrlSynapse(req);
			String redirectUrl = new OAuth2Api(AUTHORIZE_URL_SYNAPSE, TOKEN_URL_SYNAPSE).
					getAuthorizationUrl(new OAuthConfig(getClientIdSynapse(), null, redirectBackUrl, null, "openid", null));
			resp.setHeader("Location", redirectUrl+"&state=someRandomStateToPassThrough");
			resp.setStatus(303);
		} else {
			throw new RuntimeException("Unexpected URI "+req.getRequestURI());
		}
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("Error:");
				e.printStackTrace(new PrintStream(os));
			}
			resp.setStatus(500);
		}
	}
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws Exception {
		
		OAuthService service = null;
		OAuthRequest request = null;
		String result = null;
		if (req.getRequestURI().contains(GOOGLE_BUTTON_URI)) {
			service = (new OAuth2Api(AUTHORIZE_URL_GOOGLE, TOKEN_URL_GOOGLE)).
					createService(new OAuthConfig(getClientIdGoogle(), getClientSecretGoogle(), getRedirectBackUrlGoogle(req), null, null, null));
			request = new OAuthRequest(Verb.GET, GOOGLE_OAUTH_USER_INFO_API_URL);
			String authorizationCode = req.getParameter("code");
			Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
			// Use the access token to get the UserInfo from Google.
			service.signRequest(accessToken, request);
			Response response = request.send();
			if(!response.isSuccessful()){
				throw new Exception("Response code: "+response.getCode()+" Message: "+response.getMessage());
			}
			
			result = response.getBody();
		} else if (req.getRequestURI().contains(ORCID_BUTTON_URI)) {
			service = (new OAuth2Api(AUTHORIZE_URL_ORCID, TOKEN_URL_ORCID)).
					createService(new OAuthConfig(getClientIdOrcid(), getClientSecretOrcid(), getRedirectBackUrlOrcid(req), null, null, null));
			request = new OAuthRequest(Verb.GET, ORCID_OAUTH_USER_INFO_API_URL);
			String authorizationCode = req.getParameter("code");
			Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
			result = accessToken.getRawResponse();
		} else if (req.getRequestURI().contains(SYNAPSE_BUTTON_URI)) {
			service = (new OAuth2Api(AUTHORIZE_URL_SYNAPSE, TOKEN_URL_SYNAPSE)).
					createService(new OAuthConfig(getClientIdSynapse(), getClientSecretSynapse(), getRedirectBackUrlSynapse(req), null, null, null));
			String authorizationCode = req.getParameter("code");
			Token accessToken = service.getAccessToken(null, new Verifier(authorizationCode));
			result = accessToken.getRawResponse();
			request = new OAuthRequest(Verb.GET, SYNAPSE_OAUTH_USER_INFO_API_URL);
			request.addHeader("Authorization", "Bearer "+accessToken.getToken());
			Response response = request.send();
			if(!response.isSuccessful()){
				throw new Exception("Response code: "+response.getCode()+" Message: "+response.getMessage());
			}
			result = response.getBody();
		} else {
			throw new RuntimeException("Unexpected URI "+req.getRequestURI());
		}
		
		logger.log(Level.WARNING, result);
		resp.setContentType("text/plain");
		try (ServletOutputStream os=resp.getOutputStream()) {
//			os.println("redirect URL:");
//			os.println(req.getRequestURL().toString());
//			os.println("redirect request param's:");
//			os.println(req.getQueryString());
//			os.println("\nResponse Body:\n");
			os.println(result);
		}
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
