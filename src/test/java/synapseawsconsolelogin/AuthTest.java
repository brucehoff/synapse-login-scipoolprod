package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.amazonaws.services.securitytoken.model.Credentials;

@RunWith(MockitoJUnitRunner.class)
public class AuthTest {
	
	@Mock
	private HttpServletRequest req;
	
	@Test
	public void testReadTeamToArnMap() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("USER_CLAIMS", "userid,user_name");
	
		Auth auth = new Auth();
		
		Map<String,String> map = auth.getTeamToRoleMap();
		assertEquals(2, map.size());
		String key = map.keySet().iterator().next();
		assertEquals("123456", key);
		assertEquals("arn:aws:iam::foo", map.get(key));
	}
	
	@Test
	public void testGetAuthUrl() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("USER_CLAIMS", "userid,user_name");
		
		Auth auth = new Auth();
		
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}}}";
		String actual = auth.getAuthorizeUrl();
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetPropertyFromGlobalPropertiesFile() {
		String name = "testPropertyName";
		String value = "someOtherValue";
		Auth auth = new Auth();
		
		assertEquals(value, auth.getProperty(name));
		
	}

	@Test
	public void testGetPropertyOverridingFileWithProperty() {
		String name = "testPropertyName";
		String value = "someOtherValue";
		System.setProperty(name, value);
		Auth auth = new Auth();
		assertEquals(value, auth.getProperty(name));
		
	}

	@Test
	public void testGetMissingOptionalProperty() {
		Auth auth = new Auth();
		assertNull(auth.getProperty("undefined-property", false));
		
	}

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
		Auth auth = new Auth();
		String actual = auth.getConsoleLoginURL(req, credentials);
		
		String expectedPrefix = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=";
		String expectedSuffix = "&Issuer=https%3Awww.foo.com&Destination=https%3A%2F%2Fus-east-1.console.aws.amazon.com%2Fservicecatalog%2Fhome%3Fregion%3Dus-east-1%23%2Fproducts";
		
		assertTrue(actual.startsWith(expectedPrefix));
		assertTrue(actual.endsWith(expectedSuffix));
	}

}
