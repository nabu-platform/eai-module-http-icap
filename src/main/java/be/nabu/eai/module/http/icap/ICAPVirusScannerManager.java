package be.nabu.eai.module.http.icap;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class ICAPVirusScannerManager extends JAXBArtifactManager<ICAPVirusScannerConfiguration, ICAPVirusScanner> {

	public ICAPVirusScannerManager() {
		super(ICAPVirusScanner.class);
	}

	@Override
	protected ICAPVirusScanner newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new ICAPVirusScanner(id, container, repository);
	}

}
