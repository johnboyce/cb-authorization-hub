package com.connellboyce.authhub.model.dao;

import io.quarkus.mongodb.panache.common.MongoEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.codecs.pojo.annotations.BsonId;

@Data
@AllArgsConstructor
@NoArgsConstructor
@MongoEntity(collection = "scopes")
public class Scope {
	@BsonId
	private String id;
	private String name;
	private String applicationId;
}
