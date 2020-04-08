package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Map;

import org.junit.Test;

public class AuthTest {
	
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


}
