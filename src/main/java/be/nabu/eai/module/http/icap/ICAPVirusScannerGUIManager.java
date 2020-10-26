package be.nabu.eai.module.http.icap;

import java.io.IOException;
import java.util.List;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseJAXBGUIManager;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;

public class ICAPVirusScannerGUIManager extends BaseJAXBGUIManager<ICAPVirusScannerConfiguration, ICAPVirusScanner> {

	public ICAPVirusScannerGUIManager() {
		super("ICAP Virus Scanner", ICAPVirusScanner.class, new ICAPVirusScannerManager(), ICAPVirusScannerConfiguration.class);
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		return null;
	}

	@Override
	protected ICAPVirusScanner newInstance(MainController controller, RepositoryEntry entry, Value<?>...values) throws IOException {
		return new ICAPVirusScanner(entry.getId(), entry.getContainer(), entry.getRepository());
	}
	
	@Override
	public String getCategory() {
		return "Security";
	}

}
