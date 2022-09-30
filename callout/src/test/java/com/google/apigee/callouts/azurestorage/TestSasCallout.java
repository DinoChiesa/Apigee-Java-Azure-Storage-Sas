package com.google.apigee.callouts.azurestorage;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class TestSasCallout {
  MessageContext msgCtxt;
  ExecutionContext exeCtxt;

  @BeforeTest()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String,Object> variables;

          public void $init() {
              variables = new HashMap<String,Object>();
          }

          @Mock()
          @SuppressWarnings("unchecked")
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String,Object>();
            }
            T value = (T) variables.get(name);
            System.out.printf("getVariable(%s) ==> %s\n", name, (value!=null)?value.toString():"null");
            return (T) variables.get(name);
          }

          @Mock()
          @SuppressWarnings("unchecked")
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap<String,Object>();
            }
            if (name.endsWith(".stacktrace")) {
              System.out.printf("setVariable(%s, %s)\n", name, value.toString().substring(0,56)+"...");
            }
            else {
              System.out.printf("setVariable(%s, %s)\n", name,  (value!=null)?value.toString():"null");
            }
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String,Object>();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
  }

  @Test()
  public void good1() {
    Map<String,Object> m = new HashMap<String,Object>();
    m.put("key", "A3AB6FEC-972B-4F5D-B99F-9DC5AAF83698-390AB533-9D76-4351-AEDD-020EC3057A11");
    m.put("key-encoding", "UTF8");
    m.put("permissions", "r");
    m.put("ip", "168.92.3.4");
    m.put("expiry", "10m");
    m.put("version", "2018-11-09");
    m.put("debug", "true");
    m.put("resource-uri", "https://myaccount.blob.core.windows.net/container/blob.txt");
    SasCallout callout = new SasCallout(m);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("sas-error");
    String sasUri = msgCtxt.getVariable("sas-uri");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNull(error);
    Assert.assertNotNull(sasUri);
  }

  @Test()
  public void good_base64Key_defaultVersion() {
    Map<String,Object> m = new HashMap<String,Object>();
    m.put("key", "OURDNUFBRjgzNjk4LTM5MEFCNTMzLTlENzYtNDM1MS1BRURELTAyMEVDMzA1N0ExMQ==");
    m.put("key-encoding", "base64");
    m.put("permissions", "r");
    m.put("expiry", "10m");
    m.put("debug", "true");
    m.put("resource-uri", "https://myaccount.blob.core.windows.net/container/object.ext");
    SasCallout callout = new SasCallout(m);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("sas-error");
    String sasUri = msgCtxt.getVariable("sas-uri");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNull(error);
    Assert.assertNotNull(sasUri);
  }


  @Test()
  public void knownGood1() {
    Map<String,Object> m = new HashMap<String,Object>();
    m.put("key", "OURDNUFBRjgzNjk4LTM5MEFCNTMzLTlENzYtNDM1MS1BRURELTAyMEVDMzA1N0ExMQ==");
    m.put("key-encoding", "base64");
    m.put("permissions", "r");
    m.put("ip", "168.92.3.4");
    m.put("expiry", "10m");
    m.put("version", "2018-11-09");
    m.put("debug", "true");
    m.put("resource-uri", "https://myaccount.blob.core.windows.net/container/object.ext");
    SasCallout callout = new SasCallout(m);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("sas-error");
    String sasUri = msgCtxt.getVariable("sas-uri");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNull(error);
    Assert.assertNotNull(sasUri);
  }


}
