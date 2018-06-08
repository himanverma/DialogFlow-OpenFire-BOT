package com.himanshu;

import org.jdom.Element;
import org.jivesoftware.openfire.MessageRouter;
import org.jivesoftware.openfire.PacketRouter;
import org.jivesoftware.openfire.PresenceManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.jdom.Element;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Future;

import com.google.api.gax.core.CredentialsProvider;
import com.google.api.gax.rpc.ClientContext;import com.google.api.gax.rpc.ClientSettings;
import com.google.auth.Credentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.dialogflow.v2.DetectIntentResponse;
import com.google.cloud.dialogflow.v2.EventInput;
import com.google.cloud.dialogflow.v2.QueryInput;
import com.google.cloud.dialogflow.v2.QueryResult;
import com.google.cloud.dialogflow.v2.SessionName;
import com.google.cloud.dialogflow.v2.SessionsClient;
import com.google.cloud.dialogflow.v2.SessionsSettings;
import com.google.cloud.dialogflow.v2.TextInput;
import com.google.cloud.dialogflow.v2.TextInput.Builder;
import com.google.gson.Gson;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Field;
import com.google.protobuf.util.JsonFormat;
import com.google.api.client.json.JsonGenerator;
import com.google.api.gax.core.*;

import org.codehaus.jackson.map.ObjectMapper;

public class DialogFlowBot implements Plugin, PacketInterceptor {

	private static final Logger Log = LoggerFactory.getLogger(DialogFlowBot.class);

	private static final String PROPERTY_DEBUG = "plugin.dialog_flow_bot.debug";
	private static final String PROPERTY_SEND_BODY = "plugin.dialog_flow_bot.send_body";
//	private static final String PROPERTY_TOKEN = "plugin.dialog_flow_bot.token";
	
	private static final String PROPERTY_JSON_PATH = "plugin.dialog_flow_bot.google_json_path";
	private static final String PROPERTY_PROJECTID = "plugin.dialog_flow_bot.project_id";
	private static final String PROPERTY_LANG = "plugin.dialog_flow_bot.lang";
	private static final String PROPERTY_RESPONDER_JID = "plugin.dialog_flow_bot.responder_jid";
	private static final String PROPERTY_WATCH_ALL = "plugin.dialog_flow_bot.watch_all";
	private static final String PROPERTY_WATCH_KEYWORD = "plugin.dialog_flow_bot.watch_keyword";
	private static final String PROPERTY_MIN_CONFIDENCE = "plugin.dialog_flow_bot.min_confidence";

	private boolean debug;
	private boolean sendBody;

	private String url;
	private String token;
	
	private String jsonPath;
	private String projectId;
	private String projectLang;
	private boolean watchAll;
	private String watchKeyword;
	private String responderJid;
	private float minConfidence;
	
	
	private InterceptorManager interceptorManager;
	private UserManager userManager;
	private PresenceManager presenceManager;
	private Client client;
	private MessageRouter msrouter;

	public void initializePlugin(PluginManager pManager, File pluginDirectory) {
		debug = JiveGlobals.getBooleanProperty(PROPERTY_DEBUG, false);
		sendBody = JiveGlobals.getBooleanProperty(PROPERTY_SEND_BODY, true);
		jsonPath = getProperty(PROPERTY_JSON_PATH, "/var/www/GoogleDialogFlow.json");
		projectId = getProperty(PROPERTY_PROJECTID, "alphabot-204804");
		projectLang = getProperty(PROPERTY_LANG, "en-US");
		responderJid = getProperty(PROPERTY_RESPONDER_JID, "NA");
		watchAll = JiveGlobals.getBooleanProperty(PROPERTY_WATCH_ALL,true);
		watchKeyword = getProperty(PROPERTY_WATCH_KEYWORD, "bot");
		minConfidence = Float.parseFloat(getProperty(PROPERTY_MIN_CONFIDENCE, "0.0"));
		

//		url = getProperty(PROPERTY_URL, "http://localhost:8080/user/offline/callback/url");
//		token = getProperty(PROPERTY_TOKEN, UUID.randomUUID().toString());

		if (debug) {
			Log.debug("initialize DialogFlowBOT plugin. Start.");
			Log.debug("Loaded properties: \nurl={}, \ntoken={}, \nsendBody={}", new Object[] { url, token, sendBody });
		}

		interceptorManager = InterceptorManager.getInstance();
		presenceManager = XMPPServer.getInstance().getPresenceManager();
		userManager = XMPPServer.getInstance().getUserManager();
		client = ClientBuilder.newClient();
		msrouter = XMPPServer.getInstance().getMessageRouter();
		// register with interceptor manager
		interceptorManager.addInterceptor(this);

		if (debug) {
			Log.debug("initialize DialogFlowBOT plugin. Finish.");
		}
	}

	private String getProperty(String code, String defaultSetValue) {
		String value = JiveGlobals.getProperty(code, null);
		if (value == null || value.length() == 0) {
			JiveGlobals.setProperty(code, defaultSetValue);
			value = defaultSetValue;
		}
		return value;
	}

	public void destroyPlugin() {
		// unregister with interceptor manager
		interceptorManager.removeInterceptor(this);
		if (debug) {
			Log.debug("destroy DialogFlowBOT plugin.");
		}
	}
	

	public void interceptPacket(Packet packet, Session session, boolean incoming, boolean processed)
			throws PacketRejectedException {
		if (processed && incoming && packet instanceof Message && packet.getTo() != null) {

			Message msg = (Message) packet;
			JID to = packet.getTo();

			if (msg.getType() != Message.Type.chat && msg.getType() != Message.Type.groupchat) {
				return;
			}

				if (debug) {
					Log.debug("intercepted message from {} to {}, recipient is available {}",
							new Object[] { packet.getFrom().toBareJID(), to.toBareJID() });
				}

				// if (!available) {
				JID from = packet.getFrom();
				String body = sendBody ? msg.getBody() : "";
				if(debug) {
					Log.info("DialogFlowBOT: msgBody" + body);
				}
				if(body == null) {
					return;
				}
				
				if(!watchAll) {
					if (!body.toLowerCase().contains(watchKeyword)) {
						if(debug) {
							Log.info("DialogFlowBOT: " + watchKeyword +" key not detected...");
						}
						return;
					}
				}
				
				
				if(debug) {
					Log.info(" packetFrom: " + packet.getFrom());
					Log.info(" packetFromtoFullJID: " + packet.getFrom().toFullJID());
					Log.info(" packetFromBareJID: " + packet.getFrom().toBareJID());
					Log.info(" packetTo: " + packet.getTo());
				}

				Message botMsg = new Message();
				if(msg.getType() == Message.Type.groupchat) {
					Log.info(" ====== ");
					botMsg.setTo(packet.getTo().toFullJID());
					if(responderJid.equals("NA")){
						botMsg.setFrom(packet.getTo());
					}else {
						botMsg.setFrom(responderJid);
					}
					botMsg.setType(Message.Type.chat);
					Log.info("Respnse:" +  botMsg.toXML());
				}else {
					botMsg.setTo(packet.getFrom());
					if(responderJid.equals("NA")){
						botMsg.setFrom(packet.getTo());
					}else {
						botMsg.setFrom(responderJid);
					}
					botMsg.setType(msg.getType());
				}
				

				String dFlowSessionID = UUID.randomUUID().toString(); //"1daa71a3-3950-4dc4-a5d2-3d69315c53ad";
				try {
					detectIntentTexts(projectId, body, dFlowSessionID, projectLang,botMsg,msrouter,packet.getFrom().toBareJID(),packet.getTo().toBareJID());
				}catch(Exception e){
			        Log.error("DialogFlowBOT: DialogFlow exeception" + e.getMessage());
			    }
				
		}
	}

	/**
	 * Returns the result of detect intent with texts as inputs.
	 *
	 * Using the same `session_id` between requests allows continuation of the
	 * conversation.
	 * 
	 * @param projectId
	 *            Project/Agent Id.
	 * @param texts
	 *            The text intents to be detected based on what a user says.
	 * @param sessionId
	 *            Identifier of the DetectIntent session.
	 * @param languageCode
	 *            Language code of the query.
	 */
	public void detectIntentTexts(String projectId, String texts, String sessionId, String languageCode, Message botMsg, MessageRouter msrouter,String msgFrom, String msgTo)
			throws Exception {
		
		
		CredentialsProvider credentialsProvider = FixedCredentialsProvider.create(ServiceAccountCredentials.fromStream(new FileInputStream(jsonPath)));
		SessionsSettings sessionSettings = SessionsSettings.newBuilder().setCredentialsProvider(credentialsProvider).build();
		// Instantiates a client
		try (SessionsClient sessionsClient = SessionsClient.create(sessionSettings)) {
			
			// Set the session name using the sessionId (UUID) and projectID (my-project-id)
			SessionName session = SessionName.of(projectId, sessionId);
			if(debug) {
				Log.info("DialogFlowBOT: " + "Session Path: " + session.toString());
			}

			// Detect intents for each text input
			// for (String text : texts) {
			// Set the text (hello) and language code (en-US) for the query
			Builder textInput = TextInput.newBuilder()
					.setText(msgFrom + " | " + texts)
					.setLanguageCode(languageCode);
			FieldDescriptor flFrom = null;
			// Build the query with the TextInput
			QueryInput queryInput = QueryInput.newBuilder()
					.setText(textInput)
					.build();

			// Performs the detect intent request
			DetectIntentResponse response = sessionsClient.detectIntent(session, queryInput);

			// Display the query result
			QueryResult queryResult = response.getQueryResult();
			if(queryResult.getIntentDetectionConfidence() >= minConfidence) {
				botMsg.setBody(queryResult.getFulfillmentText());
				Gson gson = new Gson();
//				String jsonData = gson.toJson(response.getQueryResult().getWebhookPayload().getAllFields().values());
			    String jsonData = "";
			    try {
			    	JsonFormat.Printer printer = JsonFormat.printer();
			    	jsonData = printer.print(response.getQueryResult().toBuilder());
			    } catch (Exception e) {
			        Log.info("DialogFlowBOT: JsonWebHookParse Issue | " + e.getMessage());
			    }
				botMsg.addChildElement("data", "dialogflowbot").addText(jsonData);
				msrouter.route(botMsg);
			}
			if(debug) {
				Log.info("====================");
				Log.info("DialogFlowBOT: Query Text: " +  queryResult.getQueryText());
				Log.info("DialogFlowBOT: Detected Intent: " + queryResult.getIntent().getDisplayName() + " (confidence: " + queryResult.getIntentDetectionConfidence() + ")");
				Log.info("DialogFlowBOT: Fulfillment Text: " + queryResult.getFulfillmentText());
			}
		} catch (Exception e) {
			Log.error("DialogFlowBOT: DialogFlow Exception | " + e.getMessage());
			return; // Always must return something
		}
	}

}
