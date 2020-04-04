package synapseawsconsolelogin;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.amazonaws.services.securitytoken.model.Credentials;

@RunWith(MockitoJUnitRunner.class)
public class AuthTest {
	
	@Mock
	private HttpServletRequest req;
	
	@BeforeClass
	public static void setUp() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("USER_CLAIMS", "userid,user_name");
	}

	@Test
	public void testReadTeamToArnMap() {
		Map<String,String> map = Auth.getTeamToRoleMap();
		assertEquals(2, map.size());
		String key = map.keySet().iterator().next();
		assertEquals("123456", key);
		assertEquals("arn:aws:iam::foo", map.get(key));
	}
	
	@Test
	public void testGetAuthUrl() {
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}}}";
		String actual = Auth.getAuthorizeUrl();
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetConsoleLoginURL() throws Exception {
		StringBuffer urlBuffer = new StringBuffer();
		urlBuffer.append("https:www.foo.com/bar");
		when(req.getRequestURL()).thenReturn(urlBuffer);
		
		when(req.getRequestURI()).thenReturn("/bar");
		
		Credentials credentials = new Credentials();
		credentials.setAccessKeyId("keyId");
		credentials.setSecretAccessKey("keySecret");
		credentials.setSessionToken("token");
		
		// method under test
		String actual = Auth.getConsoleLoginURL(req, credentials);
		
		String expectedPrefix = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=";
		String expectedSuffix = "&Issuer=https%3Awww.foo.com&Destination=https%3A%2F%2Fus-east-1.console.aws.amazon.com%2Fservicecatalog%2Fhome%3Fregion%3Dus-east-1%23%2Fproducts";
		
		assertTrue(actual.startsWith(expectedPrefix));
		assertTrue(actual.endsWith(expectedSuffix));
	}

}
