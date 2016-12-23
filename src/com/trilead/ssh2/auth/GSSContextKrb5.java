package com.trilead.ssh2.auth;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;


public class GSSContextKrb5 {
	
	  private static final String PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";
	  private static final String KRB5_OID = "1.2.840.113554.1.2.2";
	  private static String USE_SUBJECTS_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";
	  private GSSContext context=null;
	  
	  public void create(String host) throws Exception{
	    try
	    {
	      // RFC 1964
	      Oid krb5=new Oid(KRB5_OID);

	      Oid principalName=new Oid(PRINCIPAL_NAME_OID);
	      
	      System.setProperty(USE_SUBJECTS_CREDS_ONLY,"false");

	      GSSManager mgr=GSSManager.getInstance();

	      String cname=host;
	      try
	      {
	    	  cname=InetAddress.getByName(cname).getCanonicalHostName();
	      }
	      catch(UnknownHostException e){
	    	  throw new Exception(e.toString());
	      }
	      
	      GSSName _host=mgr.createName("host/"+cname, principalName);

	      context=mgr.createContext(_host, krb5, null, GSSContext.DEFAULT_LIFETIME);

	      // RFC4462  3.4.  GSS-API Session
	      //
	      // When calling GSS_Init_sec_context(), the client MUST set
	      // integ_req_flag to "true" to request that per-message integrity
	      // protection be supported for this context.  In addition,
	      // deleg_req_flag MAY be set to "true" to request access delegation, if
	      // requested by the user.
	      //
	      // Since the user authentication process by its nature authenticates
	      // only the client, the setting of mutual_req_flag is not needed for
	      // this process.  This flag SHOULD be set to "false".

	      // TODO: OpenSSH's sshd does accepts 'false' for mutual_req_flag
	      //context.requestMutualAuth(false);
	      context.requestMutualAuth(true);
	      context.requestConf(true);
	      context.requestInteg(true);             // for MIC
	      context.requestCredDeleg(true);
	      context.requestAnonymity(false);

	      return;
	    }
	    catch(GSSException ex) 
	    {
	      throw new Exception(ex.toString());
	    }
	  }

	  public boolean isEstablished()
	  {
	    return context.isEstablished();
	  }

	  public byte[] init(byte[] token, int s, int l) throws Exception 
	  {
	    try
	    { 
	    	return context.initSecContext(token, 0, l);
	    }
	    catch(GSSException ex)
	    {
	    	throw new Exception(ex.toString());
	    }
	    catch(java.lang.SecurityException ex)
	    {
	    	throw new Exception(ex.toString());
	    }
	    finally
	    {
	      if(System.getProperty(USE_SUBJECTS_CREDS_ONLY)==null)
	      {
	    	  // By the default, it must be "true".
	    	  System.setProperty(USE_SUBJECTS_CREDS_ONLY, "true");
	      }
	    }
	  }

	  public byte[] getMIC(byte[] message, int s, int l) throws Exception
	  {
	    try
	    {
	    	MessageProp prop =  new MessageProp(0, true);
	    	return context.getMIC(message, s, l, prop);
	    }
	    catch(GSSException ex)
	    {
	      throw new Exception(ex.toString());
	    }
	  }

	  public void dispose() throws Exception
	  {
	    try
	    {
	      context.dispose();
	    }
	    catch(GSSException ex)
	    {
	    	throw new Exception(ex.toString());
	    }
	  }

}
