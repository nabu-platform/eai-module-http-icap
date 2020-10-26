package be.nabu.eai.module.http.icap;

import be.nabu.eai.repository.api.VirusInfection;

public class ICAPVirusInfection implements VirusInfection {
	
	public static ICAPVirusInfection from(be.nabu.libs.http.icap.VirusInfection infection) {
		ICAPVirusInfection result = new ICAPVirusInfection();
		result.setThreat(infection.getThreat());
		result.setResolution(infection.getResolution());
		result.setType(infection.getType());
		return result;
	}

	private String threat, resolution, type;

	@Override
	public String getThreat() {
		return threat;
	}
	public void setThreat(String threat) {
		this.threat = threat;
	}

	public String getResolution() {
		return resolution;
	}
	public void setResolution(String resolution) {
		this.resolution = resolution;
	}

	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	
}
