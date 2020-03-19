package synapseawsconsolelogin;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

public class AuthTest {
	
	
	@Before
	public void setUp() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
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
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true}\"family_name\":{\"essential\":true},\"given_name\":{\"essential\":true},\"email\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true}\"family_name\":{\"essential\":true},\"given_name\":{\"essential\":true},\"email\":{\"essential\":true},\"userid\":{\"essential\":true}}}";
		String actual = Auth.getAuthorizeUrl();
		assertEquals(expected, actual);
	}

}
