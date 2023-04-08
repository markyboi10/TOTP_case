/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ServerConfig;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.HashMap;
import java.io.InvalidObjectException;
import java.util.Base64;

import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.JSONSerializable;
import merrimackutil.util.Pair;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import java.security.spec.InvalidKeySpecException;
import java.io.UnsupportedEncodingException;

import merrimackutil.json.JsonIO;
import java.nio.charset.StandardCharsets;
import merrimackutil.json.parser.JSONParser;



/**
 * This class represents the vault data structure 
 * for the password manager.
 * @author Zach Kissel
 */
public class Vault implements JSONSerializable
{
	private HashMap<String, Account> accounts;


	/**
	 * Construct a new vault from a JSON Object.
	 * @param pass the password associated with the vault.
	 * @param obj the JSON object representing a vault.
	 * @throws InvalidObjectException when {@code obj} doesn't represent 
	 * a valid Vault object.
	 */
	public Vault(String pass, JSONObject obj) throws InvalidObjectException
	{

        
		

		
		accounts = new HashMap<>();
		deserialize(obj);

	}
	
//	/**
//	 * Constructs a new empty vault.
//	 */
//    public Vault(String pass)
//    {
//
//    	accounts = new HashMap<>();
//        
//
//    }

    public void addAccount(String entries, String salt, String pass, String totp_key, String user)
    {
        accounts.put(entries,new Account(salt, pass, totp_key, user));
    }




   /**
    * Serializes the object into a JSON encoded string.
    * @return a string representing the JSON form of the object.
    */
        @Override
   public String serialize()
   {
   	return toJSONType().getFormattedJSON();
   }

   /**
    * Coverts json data to an object of this type.
    * @param obj a JSON type to deserialize.
    * @throws InvalidObjectException the type does not match this object.
    */
        @Override
   public void deserialize(JSONType obj) throws InvalidObjectException
   {
    JSONObject tmp;
    JSONArray accountsArray;
    if (obj instanceof JSONObject)
    {
      tmp = (JSONObject)obj;
      if (tmp.containsKey("entries"))
        accountsArray = tmp.getArray("entries");
      else
        throw new InvalidObjectException("Expected a Vault object -- entries expected.");
    }
    else 
      throw new InvalidObjectException("Expected a Vault object -- recieved array");

  	for (int i = 0; i < accountsArray.size(); i++)
  	{
  		JSONObject currAccount = accountsArray.getObject(i);
  		accounts.put(currAccount.getString("url"), new Account(currAccount));
  	}
   }

   /**
    * Converts the object to a JSON type. 
    * @return a JSON type either JSONObject or JSONArray.
    */
        @Override
   public JSONType toJSONType()
   {
    JSONObject obj = new JSONObject();
    JSONArray accountsArray = new JSONArray();

    for (String url : accounts.keySet())
    	accountsArray.add(accounts.get(url).toJSONType());
    
    obj.put("entries", accountsArray);
    return obj;
   }


}
