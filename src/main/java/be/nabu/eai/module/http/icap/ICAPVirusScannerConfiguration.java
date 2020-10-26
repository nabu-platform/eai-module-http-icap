package be.nabu.eai.module.http.icap;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.EnvironmentSpecific;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.types.api.annotation.Field;

@XmlRootElement(name = "virusScanner")
public class ICAPVirusScannerConfiguration {
	private KeyStoreArtifact keystore;
	private boolean secure;
	private String host, path;

	@EnvironmentSpecific
	public boolean isSecure() {
		return secure;
	}
	public void setSecure(boolean secure) {
		this.secure = secure;
	}
	
	@Field(show = "secure", comment = "Set a custom keystore if necessary")
	@EnvironmentSpecific
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public KeyStoreArtifact getKeystore() {
		return keystore;
	}
	public void setKeystore(KeyStoreArtifact keystore) {
		this.keystore = keystore;
	}
	
	@EnvironmentSpecific
	public String getHost() {
		return host;
	}
	public void setHost(String host) {
		this.host = host;
	}
	
	@EnvironmentSpecific
	public String getPath() {
		return path;
	}
	public void setPath(String path) {
		this.path = path;
	}
	
}
