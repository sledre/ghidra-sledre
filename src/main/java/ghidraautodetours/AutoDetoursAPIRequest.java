package ghidraautodetours;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class AutoDetoursAPIRequest {
	public static <T> T get(URL url, Class<T> t) throws IOException {
		T obj = null;
		
		String[] acceptHeader = {"Accept", "application/json"};
		String response = rawGet(url, acceptHeader);
		
		if (response != null) {
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			obj = gson.fromJson(response, t);
		}
		return obj;
	}
	
	public static String rawGet(URL url, String[]... properties) throws IOException {
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("GET");
		con.setConnectTimeout(5000);
		con.setReadTimeout(5000);
		con.setInstanceFollowRedirects(true);
		
		// override default properties with user params
		for(String[] property : properties) {
			con.setRequestProperty(property[0],property[1]);
		}

		int status = con.getResponseCode();

		String response = null;
		if (status == 200) {
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer responseBuilder = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				responseBuilder.append(inputLine);
				responseBuilder.append('\n');
			}
			in.close();
			response = responseBuilder.toString();
		}
		
		con.disconnect();
		return response;
	}
}
