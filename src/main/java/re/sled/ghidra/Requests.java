package re.sled.ghidra;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class Requests {
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
	
	public static <T1, T2> T2 post(URL url, T1 t1, Class<T2> t2) throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		T2 obj = null;
		
		String[] acceptHeader = {"Accept", "application/json"};
		String[] contentTypeHeader = {"Content-Type", "application/json"};
		String data = gson.toJson(t1);
		String response = rawPost(url, data, acceptHeader, contentTypeHeader);
		
		if (response != null) {
			
			obj = gson.fromJson(response, t2);
		}
		return obj;
	}
	
	public static String rawPost(URL url, String data, String[]... properties) throws IOException {
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setConnectTimeout(5000);
		con.setReadTimeout(5000);
		con.setInstanceFollowRedirects(true);
		
		// override default properties with user params
		for(String[] property : properties) {
			con.setRequestProperty(property[0],property[1]);
		}
		
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(data);
		wr.flush();
		wr.close();

		int status = con.getResponseCode();

		String response = null;
		if (status == 201) {
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
	
	public static void connectivityCheck(URL url) throws IOException {
		URL checkURL = new URL(url, "/api/");
		String response = rawGet(checkURL);
		if (response == null) {
			throw new IOException("Connectivity check failed!");
		}
	}
}
