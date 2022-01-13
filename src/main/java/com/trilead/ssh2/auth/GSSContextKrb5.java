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
	  private static final String USE_SUBJECTS_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";
	  private GSSContext context=null;
	  
	  public void create(String host) throws UnknownHostException, GSSException {
	      // RFC 1964
	      Oid krb5=new Oid(KRB5_OID);

	      Oid principalName=new Oid(PRINCIPAL_NAME_OID);
	      
	      System.setProperty(USE_SUBJECTS_CREDS_ONLY,"false");

	      GSSManager mgr=GSSManager.getInstance();

	      String cname=InetAddress.getByName(host).getCanonicalHostName();
	      
	      GSSName gssHost=mgr.createName("host/"+cname, principalName);

	      context=mgr.createContext(gssHost, krb5, null, GSSContext.DEFAULT_LIFETIME);

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
	  }

	  public boolean isEstablished()
	  {
	    return context.isEstablished();
	  }

	  public byte[] init(byte[] token, int s, int l) throws GSSException, SecurityException 
	  {
	    try
	    { 
	    	return context.initSecContext(token, 0, l);
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

	  public byte[] getMIC(byte[] message, int s, int l) throws GSSException
	  {
	    	MessageProp prop =  new MessageProp(0, true);
	    	return context.getMIC(message, s, l, prop);
	  }

	  public void dispose() throws GSSException
	  {
	      context.dispose();
	  }

}
