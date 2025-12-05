package com.connellboyce.authhub;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;

@QuarkusMain
public class AuthHubApplication {

	public static void main(String[] args) {
		Quarkus.run(args);
	}

}
