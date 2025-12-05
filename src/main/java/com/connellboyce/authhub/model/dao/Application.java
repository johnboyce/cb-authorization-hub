package com.connellboyce.authhub.model.dao;

import io.quarkus.mongodb.panache.common.MongoEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.codecs.pojo.annotations.BsonId;

@Data
@AllArgsConstructor
@NoArgsConstructor
@MongoEntity(collection = "applications")
public class Application {
	@BsonId
	private String id;
	private String name;
	private String description;
	private String ownerId;
}
