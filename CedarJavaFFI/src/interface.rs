/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use cedar_policy::{entities_errors::EntitiesError, EntityTypeName};
#[cfg(feature = "partial-eval")]
use cedar_policy::ffi::is_authorized_partial_json_str;
use cedar_policy::{
    ffi::{is_authorized_json_str, validate_json_str},
    Entities, EntityUid, Policy, PolicySet, Schema, Template,
};
use cedar_policy_formatter::{policies_str_to_pretty, Config};
use jni::{
    objects::{JClass, JObject, JString, JValue, JValueGen, JValueOwned},
    sys::{jstring, jvalue},
    JNIEnv,
};
use jni_fn::jni_fn;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, Value};
use std::{any::Any, collections::HashMap, error::Error, str::FromStr, thread};

use crate::objects::JFormatterConfig;
use crate::{
    answer::Answer,
    jmap::Map,
    jset::Set,
    objects::{JEntityId, JEntityTypeName, JEntityUID, JPolicy, Object},
    utils::raise_npe,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const V0_AUTH_OP: &str = "AuthorizationOperation";
#[cfg(feature = "partial-eval")]
const V0_AUTH_PARTIAL_OP: &str = "AuthorizationPartialOperation";
const V0_VALIDATE_OP: &str = "ValidateOperation";
const V0_VALIDATE_ENTITIES: &str = "ValidateEntities";

fn build_err_obj(env: &JNIEnv<'_>, err: &str) -> jstring {
    env.new_string(
        serde_json::to_string(&Answer::fail_bad_request(vec![format!(
            "Failed {} Java string",
            err
        )]))
        .expect("could not serialise response"),
    )
    .expect("error creating Java string")
    .into_raw()
}

fn call_cedar_in_thread(call_str: String, input_str: String) -> String {
    call_cedar(&call_str, &input_str)
}

/// JNI entry point for authorization and validation requests
#[jni_fn("com.cedarpolicy.BasicAuthorizationEngine")]
pub fn callCedarJNI(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    j_call: JString<'_>,
    j_input: JString<'_>,
) -> jstring {
    let j_call_str: String = match env.get_string(&j_call) {
        Ok(call_str) => call_str.into(),
        _ => return build_err_obj(&env, "getting"),
    };

    let mut j_input_str: String = match env.get_string(&j_input) {
        Ok(s) => s.into(),
        Err(_) => return build_err_obj(&env, "parsing"),
    };
    j_input_str.push(' ');

    let handle = thread::spawn(move || call_cedar_in_thread(j_call_str, j_input_str));

    let result = match handle.join() {
        Ok(s) => s,
        Err(e) => format!("Authorization thread failed {e:?}"),
    };

    let res = env.new_string(result);
    match res {
        Ok(r) => r.into_raw(),
        _ => env
            .new_string(
                serde_json::to_string(&Answer::fail_internally(
                    "Failed creating Java string".to_string(),
                ))
                .expect("could not serialise response"),
            )
            .expect("error creating Java string")
            .into_raw(),
    }
}

/// JNI entry point to get the Cedar version
#[jni_fn("com.cedarpolicy.BasicAuthorizationEngine")]
pub fn getCedarJNIVersion(env: JNIEnv<'_>) -> jstring {
    env.new_string("4.0")
        .expect("error creating Java string")
        .into_raw()
}

pub(crate) fn call_cedar(call: &str, input: &str) -> String {
    let result = match call {
        V0_AUTH_OP => is_authorized_json_str(input),
        #[cfg(feature = "partial-eval")]
        V0_AUTH_PARTIAL_OP => is_authorized_partial_json_str(input),
        V0_VALIDATE_OP => validate_json_str(input),
        V0_VALIDATE_ENTITIES => json_validate_entities(&input),
        _ => {
            let ires = Answer::fail_internally(format!("unsupported operation: {}", call));
            serde_json::to_string(&ires)
        }
    };
    result.unwrap_or_else(|err| {
        panic!("failed to handle call {call} with input {input}\nError: {err}")
    })
}

#[derive(Serialize, Deserialize)]
struct ValidateEntityCall {
    schema: Value,
    entities: Value,
}

pub fn json_validate_entities(input: &str) -> serde_json::Result<String> {
    let ans = validate_entities(input)?;
    serde_json::to_string(&ans)
}

/// public string-based JSON interface to be invoked by FFIs. Takes in a `ValidateEntityCall` and (if successful)
/// returns unit value () which is null value when serialized to json.
pub fn validate_entities(input: &str) -> serde_json::Result<Answer> {
    let validate_entity_call = from_str::<ValidateEntityCall>(&input)?;
    match Schema::from_json_value(validate_entity_call.schema) {
        Err(e) => Ok(Answer::fail_bad_request(vec![e.to_string()])),
        Ok(schema) => {
            match Entities::from_json_value(validate_entity_call.entities, Some(&schema)) {
                Err(error) => {
                    let err_message = match error {
                        EntitiesError::Serialization(err) => err.to_string(),
                        EntitiesError::Deserialization(err) => err.to_string(),
                        EntitiesError::Duplicate(err) => err.to_string(),
                        EntitiesError::TransitiveClosureError(err) => err.to_string(),
                        EntitiesError::InvalidEntity(err) => err.to_string(),
                    };
                    Ok(Answer::fail_bad_request(vec![err_message]))
                }
                Ok(_entities) => Ok(Answer::Success {
                    result: "null".to_string(),
                }),
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JavaInterfaceCall {
    pub call: String,
    arguments: String,
}

fn jni_failed(env: &mut JNIEnv<'_>, e: &dyn Error) -> jvalue {
    // If we already generated an exception, then let that go up the stack
    // Otherwise, generate a cedar InternalException and return null
    if !env.exception_check().unwrap_or_default() {
        // We have to unwrap here as we're doing exception handling
        // If we don't have the heap space to create an exception, the only valid move is ending the process
        env.throw_new(
            "com/cedarpolicy/model/exception/InternalException",
            format!("Internal JNI Error: {e}"),
        )
        .unwrap();
    }
    JValueOwned::Object(JObject::null()).as_jni()
}

/// Public string-based JSON interface to parse a schema in Cedar's JSON format
#[jni_fn("com.cedarpolicy.model.schema.Schema")]
pub fn parseJsonSchemaJni<'a>(mut env: JNIEnv<'a>, _: JClass, schema_jstr: JString<'a>) -> jvalue {
    match parse_json_schema_internal(&mut env, schema_jstr) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

/// public string-based JSON interface to parse a schema in Cedar's cedar-readable format
#[jni_fn("com.cedarpolicy.model.schema.Schema")]
pub fn parseCedarSchemaJni<'a>(mut env: JNIEnv<'a>, _: JClass, schema_jstr: JString<'a>) -> jvalue {
    match parse_cedar_schema_internal(&mut env, schema_jstr) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

fn parse_json_schema_internal<'a>(
    env: &mut JNIEnv<'a>,
    schema_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if schema_jstr.is_null() {
        raise_npe(env)
    } else {
        let schema_jstring = env.get_string(&schema_jstr)?;
        let schema_string = String::from(schema_jstring);
        match Schema::from_json_str(&schema_string) {
            Err(e) => Err(Box::new(e)),
            Ok(_) => Ok(JValueGen::Object(env.new_string("success")?.into())),
        }
    }
}

fn parse_cedar_schema_internal<'a>(
    env: &mut JNIEnv<'a>,
    schema_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if schema_jstr.is_null() {
        raise_npe(env)
    } else {
        let schema_jstring = env.get_string(&schema_jstr)?;
        let schema_string = String::from(schema_jstring);
        match Schema::from_cedarschema_str(&schema_string) {
            Err(e) => Err(Box::new(e)),
            Ok(_) => Ok(JValueGen::Object(env.new_string("success")?.into())),
        }
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn parsePolicyJni<'a>(mut env: JNIEnv<'a>, _: JClass, policy_jstr: JString<'a>) -> jvalue {
    match parse_policy_internal(&mut env, policy_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(policy_text) => policy_text.as_jni(),
    }
}

fn parse_policy_internal<'a>(
    env: &mut JNIEnv<'a>,
    policy_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policy_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_jstring = env.get_string(&policy_jstr)?;
        let policy_string = String::from(policy_jstring);
        match Policy::from_str(&policy_string) {
            Err(e) => Err(Box::new(e)),
            Ok(p) => {
                let policy_text = format!("{}", p);
                Ok(JValueGen::Object(env.new_string(&policy_text)?.into()))
            }
        }
    }
}

#[jni_fn("com.cedarpolicy.model.policy.PolicySet")]
pub fn parsePoliciesJni<'a>(mut env: JNIEnv<'a>, _: JClass, policies_jstr: JString<'a>) -> jvalue {
    match parse_policies_internal(&mut env, policies_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(policies_set) => policies_set.as_jni(),
    }
}

pub fn parse_policy_set_to_text_map(input: &str,) -> Result<(Vec<(String, String)>, Vec<(String, String)>)> 
{
    let policy_set = PolicySet::from_str(input)?;
    let policies = policy_set.policies().map(|p| (p.id().to_string(), p.to_string())).collect();

    let templates = policy_set.templates().map(|t| (t.id().to_string(), t.to_string())).collect();
    // first string is ID second is Policy - same with templates
    Ok((policies, templates))
}

fn parse_policies_internal<'a>(
    env: &mut JNIEnv<'a>,
    policies_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policies_jstr.is_null() {
        raise_npe(env)
    } else {
        let policies_jstring = env.get_string(&policies_jstr)?;
        let policies_string = String::from(policies_jstring);
       
        match parse_policy_set_to_text_map(&policies_string)
        {
            Ok((policies,templates)) => 
            {
                let policies_set = build_java_policy_set(env, policies)?;
                let template_set = build_java_policy_set(env, templates)?;

                let policy_set_obj = create_java_policy_set(env, policies_set.as_ref(), template_set.as_ref())?; //unknown 
                Ok(JValueGen::Object(policy_set_obj))
            }
    
            Err(e) => Err(e)
        }
    }
}
    fn build_java_policy_set<'a>(env: &mut JNIEnv<'a>,entries: Vec<(String, String)>,)-> Result<Set<'a, JPolicy<'a>>>  {
    let mut set = Set::new(env)?;
    for (id, text) in entries {
        let j_id = env.new_string(id)?;
        let j_text = env.new_string(text)?;
        let policy_obj = JPolicy::new(env, &j_text, &j_id)?; 
        set.add(env, policy_obj)?; 
    }
    Ok(set)
}
fn create_java_policy_set<'a>(
    env: &mut JNIEnv<'a>,
    policies_java_hash_set: &JObject<'a>, 
    templates_java_hash_set: &JObject<'a>, 
) -> Result<JObject<'a>> { 
    let policy_set_obj = env.new_object( 
        "com/cedarpolicy/model/policy/PolicySet",
        "(Ljava/util/Set;Ljava/util/Set;)V", 
        &[
            JValueGen::Object(policies_java_hash_set), 
            JValueGen::Object(templates_java_hash_set),
        ],
    )?; 
    
    Ok(policy_set_obj) }


#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn getPolicyAnnotationsJni<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    policy_jstr: JString<'a>,
) -> jvalue {
    match get_policy_annotations_internal(&mut env, policy_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(annotations) => annotations.as_jni(),
    }
}

pub fn get_policy_annotations_internal<'a>(
    env: &mut JNIEnv<'a>,
    policy_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policy_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_jstring = env.get_string(&policy_jstr)?;
        let policy_string = String::from(policy_jstring);

        match Policy::from_str(&policy_string) {
            Err(e) => Err(Box::new(e)),
            Ok(policy) => {
                let java_map = create_java_map_from_annotations(env, policy.annotations());
                Ok(JValueGen::Object(java_map))
            }
        }
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn getTemplateAnnotationsJni<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    template_jstr: JString<'a>,
) -> jvalue {
    match get_template_annotations_internal(&mut env, template_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(annotations) => annotations.as_jni(),
    }
}

pub fn get_template_annotations_internal<'a>(
    env: &mut JNIEnv<'a>,
    template_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if template_jstr.is_null() {
        raise_npe(env)
    } else {
        let template_jstring = env.get_string(&template_jstr)?;
        let template_string = String::from(template_jstring);

        match Template::from_str(&template_string) {
            Err(e) => Err(Box::new(e)),
            Ok(template) => {
                let java_map = create_java_map_from_annotations(env, template.annotations());
                Ok(JValueGen::Object(java_map))
            }
        }
    }
}

fn create_java_map_from_annotations<'a, 'b>(
    env: &mut JNIEnv<'a>,
    annotations: impl Iterator<Item = (&'b str, &'b str)>,
) -> JObject<'a> {
    let mut map = Map::new(env).unwrap();

    for (annotation_key, annotation_value) in annotations {
        let key: JString = env.new_string(annotation_key).unwrap().into();
        let value: JString = env.new_string(annotation_value).unwrap().into();
        map.put(env, key, value).unwrap();
    }

    map.into_inner()
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn parsePolicyTemplateJni<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    template_jstr: JString<'a>,
) -> jvalue {
    match parse_policy_template_internal(&mut env, template_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(template_text) => template_text.as_jni(),
    }
}

fn parse_policy_template_internal<'a>(
    env: &mut JNIEnv<'a>,
    template_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if template_jstr.is_null() {
        raise_npe(env)
    } else {
        let template_jstring = env.get_string(&template_jstr)?;
        let template_string = String::from(template_jstring);
        match Template::from_str(&template_string) {
            Err(e) => Err(Box::new(e)),
            Ok(template) => {
                let template_text = template.to_string();
                Ok(JValueGen::Object(env.new_string(&template_text)?.into()))
            }
        }
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn toJsonJni<'a>(mut env: JNIEnv<'a>, _: JClass, policy_jstr: JString<'a>) -> jvalue {
    match to_json_internal(&mut env, policy_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(policy_json) => policy_json.as_jni(),
    }
}

fn to_json_internal<'a>(env: &mut JNIEnv<'a>, policy_jstr: JString<'a>) -> Result<JValueOwned<'a>> {
    if policy_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_jstring = env.get_string(&policy_jstr)?;
        let policy_string = String::from(policy_jstring);
        let policy = Policy::from_str(&policy_string)?;
        let policy_json = serde_json::to_string(&policy.to_json().unwrap())?;
        Ok(JValueGen::Object(env.new_string(&policy_json)?.into()))
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn policyEffectJni<'a>(mut env: JNIEnv<'a>, _: JClass, policy_jstr: JString<'a>) -> jvalue {
    match policy_effect_jni_internal(&mut env, policy_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(effect) => effect.as_jni(),
    }
}

fn policy_effect_jni_internal<'a>(
    env: &mut JNIEnv<'a>,
    policy_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policy_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_jstring = env.get_string(&policy_jstr)?;
        let policy_string = String::from(policy_jstring);
        let policy = Policy::from_str(&policy_string)?;
        let policy_effect = policy.effect().to_string();
        Ok(JValueGen::Object(env.new_string(&policy_effect)?.into()))
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn templateEffectJni<'a>(mut env: JNIEnv<'a>, _: JClass, policy_jstr: JString<'a>) -> jvalue {
    match template_effect_jni_internal(&mut env, policy_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(effect) => effect.as_jni(),
    }
}

fn template_effect_jni_internal<'a>(
    env: &mut JNIEnv<'a>,
    policy_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policy_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_jstring = env.get_string(&policy_jstr)?;
        let policy_string = String::from(policy_jstring);
        let policy = Template::from_str(&policy_string)?;
        let policy_effect = policy.effect().to_string();
        Ok(JValueGen::Object(env.new_string(&policy_effect)?.into()))
    }
}

#[jni_fn("com.cedarpolicy.model.policy.Policy")]
pub fn fromJsonJni<'a>(mut env: JNIEnv<'a>, _: JClass, policy_json_jstr: JString<'a>) -> jvalue {
    match from_json_internal(&mut env, policy_json_jstr) {
        Err(e) => jni_failed(&mut env, e.as_ref()),
        Ok(policy_text) => policy_text.as_jni(),
    }
}

fn from_json_internal<'a>(
    env: &mut JNIEnv<'a>,
    policy_json_jstr: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if policy_json_jstr.is_null() {
        raise_npe(env)
    } else {
        let policy_json_jstring = env.get_string(&policy_json_jstr)?;
        let policy_json_string = String::from(policy_json_jstring);
        let policy_json_value: Value = serde_json::from_str(&policy_json_string)?;
        match Policy::from_json(None, policy_json_value) {
            Err(e) => Err(Box::new(e)),
            Ok(p) => {
                let policy_text = format!("{}", p);
                Ok(JValueGen::Object(env.new_string(&policy_text)?.into()))
            }
        }
    }
}

#[jni_fn("com.cedarpolicy.value.EntityIdentifier")]
pub fn getEntityIdentifierRepr<'a>(mut env: JNIEnv<'a>, _: JClass, obj: JObject<'a>) -> jvalue {
    match get_entity_identifier_repr_internal(&mut env, obj) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

pub fn get_entity_identifier_str<'a>(entity_id: &JEntityId<'a>) -> String
{
    entity_id.get_string_repr()
}

fn get_entity_identifier_repr_internal<'a>(
    env: &mut JNIEnv<'a>,
    obj: JObject<'a>,
) -> Result<JValueOwned<'a>> {
    if obj.is_null() {
        return raise_npe(env);
    }
    //cast wrapper
    let eid = JEntityId::cast(env, obj)?;

    //Error handling
    let repr = get_entity_identifier_str(&eid);
    let jstring = env.new_string(&repr)?;
    Ok(JValueGen::Object(jstring.into()))

}

#[jni_fn("com.cedarpolicy.value.EntityTypeName")]
pub fn parseEntityTypeName<'a>(mut env: JNIEnv<'a>, _: JClass, obj: JString<'a>) -> jvalue {
    match parse_entity_type_name_internal(&mut env, obj) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

fn parse_entity_type_name_str(input: &str) -> Result<EntityTypeName>
{
    EntityTypeName::from_str(input).map_err(|e| Box::new(e) as _)
}
pub fn parse_entity_type_name_internal<'a>(
    env: &mut JNIEnv<'a>,
    obj: JString<'a>,
) -> Result<JValueGen<JObject<'a>>> {
    if obj.is_null() {
        raise_npe(env)
    } else {
        let input_str: String = env.get_string(&obj)?.into();
        let entity_type = parse_entity_type_name_str(&input_str)?;
        let j_entity_type_name =JEntityTypeName::try_from(env, &entity_type)?;
        Ok(j_entity_type_name.into())
    }
}

#[jni_fn("com.cedarpolicy.value.EntityTypeName")]
pub fn getEntityTypeNameRepr<'a>(mut env: JNIEnv<'a>, _: JClass, obj: JObject<'a>) -> jvalue {
    match get_entity_type_name_repr_internal(&mut env, obj) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

fn get_entity_type_name_repr_internal<'a>(
    env: &mut JNIEnv<'a>,
    obj: JObject<'a>,
) -> Result<JValueOwned<'a>> {
    if obj.is_null() {
        raise_npe(env)
    } else {
        let etype = JEntityTypeName::cast(env, obj)?;
        let repr = etype.get_string_repr();
        Ok(env.new_string(repr)?.into())
    }
}

#[jni_fn("com.cedarpolicy.value.EntityUID")]
pub fn parseEntityUID<'a>(mut env: JNIEnv<'a>, _: JClass, obj: JString<'a>) -> jvalue {
    let r = match parse_entity_uid_internal(&mut env, obj) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    };
    r
}

pub fn parse_entity_uid_internal_str(euid_str: &str) -> std::result::Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let cedar_euid = EntityUid::from_str(euid_str)?;
    let mut result = HashMap::new();
    result.insert("id".to_string(), format!("{:?}", cedar_euid.type_id()));

    result.insert("type".to_string(), cedar_euid.type_name().to_string());
    Ok(result)
}

fn parse_entity_uid_internal<'a>(
    env: &mut JNIEnv<'a>,
    obj: JString<'a>,
) -> Result<JValueOwned<'a>> {
    if obj.is_null() {
        return raise_npe(env); 
    }

    let jstring_wrapper = env.get_string(&obj)?; 
    let src = jstring_wrapper.to_str()?; 
    let parsed_result_map = parse_entity_uid_internal_str(src)?; 
    let map_obj = env.new_object("java/util/HashMap", "()V", &[])?;
        for (key, value) in parsed_result_map {
        let j_key_string = env.new_string(key)?;
        let j_value_string = env.new_string(value)?;
        env.call_method(
            &map_obj, 
            "put",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", 
            &[JValueGen::Object(&j_key_string), JValueGen::Object(&j_value_string)], 
        )?;
    }
    
    Ok(JValueOwned::Object(map_obj)) 
}

#[jni_fn("com.cedarpolicy.value.EntityUID")]
pub fn getEUIDRepr<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    type_name: JObject<'a>,
    id: JObject<'a>,
) -> jvalue {
    let r = match get_euid_repr_internal(&mut env, type_name, id) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    };
    r
}

fn get_euid_repr_internal<'a>(
    env: &mut JNIEnv<'a>,
    type_name: JObject<'a>,
    id: JObject<'a>,
) -> Result<JValueOwned<'a>> {
    if type_name.is_null() || id.is_null() {
        raise_npe(env)
    } else {
        let etype = JEntityTypeName::cast(env, type_name)?.get_rust_repr();
        let id = JEntityId::cast(env, id)?.get_rust_repr();
        let euid = EntityUid::from_type_name_and_id(etype, id);
        let jstring = env.new_string(euid.to_string())?;
        Ok(jstring.into())
    }
}

#[jni_fn("com.cedarpolicy.formatter.PolicyFormatter")]
pub fn policiesStrToPretty<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    policies_jstr: JString<'a>,
) -> jvalue {
    match policies_str_to_pretty_internal(&mut env, policies_jstr, None) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

#[jni_fn("com.cedarpolicy.formatter.PolicyFormatter")]
pub fn policiesStrToPrettyWithConfig<'a>(
    mut env: JNIEnv<'a>,
    _: JClass,
    policies_jstr: JString<'a>,
    config_obj: JObject<'a>,
) -> jvalue {
    match policies_str_to_pretty_internal(&mut env, policies_jstr, Some(config_obj)) {
        Ok(v) => v.as_jni(),
        Err(e) => jni_failed(&mut env, e.as_ref()),
    }
}

fn format_policies_str_with_config(input: &str, config: &Config) -> std::result::Result<String, Box<dyn std::error::Error>> {
    policies_str_to_pretty(input, config)
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))
}

fn policies_str_to_pretty_internal<'a>(
    env: &mut JNIEnv<'a>,
    policies_jstr: JString<'a>,
    config_obj: Option<JObject<'a>>,
) -> Result<JValueOwned<'a>> {
    if policies_jstr.is_null() || config_obj.as_ref().is_some_and(|obj| obj.is_null()) {
        raise_npe(env)
    } else {
        let config = if let Some(obj) = config_obj
        {
            JFormatterConfig::cast(env, obj)?.get_rust_repr()
        }
        else
        {
            Config::default()
        };
        let policies_str = String::from(env.get_string(&policies_jstr)?);
        let formatted_string = format_policies_str_with_config(&policies_str, &config)?;
        Ok(env.new_string(formatted_string)?.into())
    }
}
#[cfg(test)]
mod jvm_based_tests {
    use super::*;
    use crate::jvm_test_utils::*;
    use jni::JavaVM;
    use std::sync::LazyLock;

    // Static JVM to be used by all the tests. LazyLock for thread-safe lazy initialization
    static JVM: LazyLock<JavaVM> = LazyLock::new(|| create_jvm().unwrap());

    mod policy_tests {
        use std::result;

        use cedar_policy::Effect;

        use super::*;

        #[track_caller]
        fn policy_effect_test_util(env: &mut JNIEnv, policy: &str, expected_effect: &str) {
            let policy_string = env.new_string(policy).unwrap();
            let effect_result = policy_effect_jni_internal(env, policy_string).unwrap();
            let effect_jstr = JString::cast(env, effect_result.l().unwrap()).unwrap();
            let effect = String::from(env.get_string(&effect_jstr).unwrap());
            assert_eq!(effect, expected_effect);
        }

        #[test]
        fn policy_effect_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            policy_effect_test_util(&mut env, "permit(principal,action,resource);", "permit");
            policy_effect_test_util(&mut env, "forbid(principal,action,resource);", "forbid");
        }

        #[track_caller]
        fn assert_id_annotation_eq(
            env: &mut JNIEnv,
            annotations: &JObject,
            annotation_key: &str,
            expected_annotation_value: &str,
        ) {
            let annotation_key_jstr = env.new_string(annotation_key).unwrap();
            let actual_annotation_value_obj = env
                .call_method(
                    annotations,
                    "get",
                    "(Ljava/lang/Object;)Ljava/lang/Object;",
                    &[JValueGen::Object(annotation_key_jstr.as_ref())],
                )
                .unwrap()
                .l()
                .unwrap();

            let actual_annotation_value_jstr =
                JString::cast(env, actual_annotation_value_obj).unwrap();
            let actual_annotation_value_str =
                String::from(env.get_string(&actual_annotation_value_jstr).unwrap());

            assert_eq!(
                actual_annotation_value_str, expected_annotation_value,
                "Returned annotation value should match the annotation in the policy."
            )
        }

        #[test]
        fn static_policy_annotations_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            let policy_string = env
                .new_string("@id(\"policyID1\") @myAnnotationKey(\"myAnnotatedValue\") permit(principal,action,resource);")
                .unwrap();
            let annotations = get_policy_annotations_internal(&mut env, policy_string)
                .unwrap()
                .l()
                .unwrap();

            assert_id_annotation_eq(&mut env, &annotations, "id", "policyID1");
            assert_id_annotation_eq(
                &mut env,
                &annotations,
                "myAnnotationKey",
                "myAnnotatedValue",
            );
        }

        #[test]
        fn template_policy_annotations_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            let policy_string = env
                .new_string("@id(\"policyID1\") @myAnnotationKey(\"myAnnotatedValue\") permit(principal==?principal,action,resource);")
                .unwrap();
            let annotations = get_template_annotations_internal(&mut env, policy_string)
                .unwrap()
                .l()
                .unwrap();

            assert_id_annotation_eq(&mut env, &annotations, "id", "policyID1");
            assert_id_annotation_eq(
                &mut env,
                &annotations,
                "myAnnotationKey",
                "myAnnotatedValue",
            );
        }
        #[test]
        fn parse_policy_internal_valid() {
            let mut env = JVM.attach_current_thread().unwrap();
            let input = r#"permit(principal,action,resource);"#;
            let policy_jstr = env.new_string(input).unwrap();
            
            let result = parse_policy_internal(&mut env, policy_jstr);
            assert!(result.is_ok(), "Expected parse_policy_internal to succeed: {:?}", result);

            let jvalue = result.unwrap();
            let parsed_jstring = JString::cast(&mut env, jvalue.l().unwrap()).unwrap();
            let actual_parsed_string = String::from(env.get_string(&parsed_jstring).unwrap());
            let expected_policy_object = cedar_policy::Policy::from_str(input).unwrap();
            let expected_canonical_string = format!("{}", expected_policy_object);
            assert_eq!(
                actual_parsed_string,
                expected_canonical_string,
                "Parsed policy string should match the expected canonical format."
            );
        }
         #[test]
        fn parse_policy_internal_invalid_missing_template_slots() {
            let mut env = JVM.attach_current_thread().unwrap();
            let input = r#"permit(principal == User::"alice", action == Action::"read", resource == Resource::"file");"#;
            let jstr = env.new_string(input).unwrap();

            let result = parse_policy_template_internal(&mut env, jstr);

            assert!(
                result.is_err(),
                "Expected parse_policy_template_internal to fail due to missing template slots"
            );
        }
        #[test]
        fn parse_policies_internal_invalid(){
            let mut env = JVM.attach_current_thread().unwrap();

            let invalid_input = "not a valid input";
            let policy_jstr = env.new_string(invalid_input).unwrap();

            let result = parse_policies_internal(&mut env, policy_jstr);
            assert!(result.is_err(), "Expected to fail or invalid input");
        }
        #[test]
        fn parse_policy_template_valid_test() {
            let mut env = JVM.attach_current_thread().unwrap();
            let policy_template = r#"permit(principal==?principal,action == Action::"readfile",resource==?resource );"#;
            let jstr = env.new_string(policy_template).unwrap();
            let result = parse_policy_template_internal(&mut env, jstr);
            assert!(result.is_ok());
        }

        #[test]
        fn parse_policy_template_invalid_test() {
            let mut env = JVM.attach_current_thread().unwrap();
            let invalid_input = r#"permit(Principa,Action,Resource );"#;
            let jstr = env.new_string(invalid_input).unwrap();
            let result = parse_policy_template_internal(&mut env, jstr);
            assert!(result.is_err(),"Expected to fail for invalid input");
         }
         #[test]
fn from_json_test_valid() {
    let mut env = JVM.attach_current_thread().unwrap();

    let policy_json = r#"
    {
        "effect": "permit",
        "principal": {
            "op": "==",
            "entity": { "type": "User", "id": "12UA45" }
        },
        "action": {
            "op": "==",
            "entity": { "type": "Action", "id": "view" }
        },
        "resource": {
            "op": "in",
            "entity": { "type": "Folder", "id": "abc" }
        },
        "conditions": [
            {
                "kind": "when",
                "body": {
                    "==": {
                        "left": {
                            ".": {
                                "left": { "Var": "context" },
                                "attr": "tls_version"
                            }
                        },
                        "right": { "Value": "1.3" }
                    }
                }
            }
        ]
    }
    "#;

    let jstr = env.new_string(policy_json).unwrap();
    let result = from_json_internal(&mut env, jstr);
    assert!(result.is_ok(), "Expected from_json parsing to succeed, got: {:?}", result);

    let jval = result.unwrap();
    let obj = jval.l().unwrap();
    let str_val: String = env.get_string(&obj.into()).unwrap().into();
    assert!(
        str_val.to_lowercase().contains("permit"),
        "Expected 'permit' in the policy string, got: '{}'",
        str_val
    );
}

 #[test]
    fn from_json_invalid()
    {
        let mut env = JVM.attach_current_thread().unwrap();
        let invalid_input = r#"
        {
            "Effect": "permit",
            "Principal": {
                "op": "==",
                "Entity": { "type": "User", "id": "12UA45" }
            },
            "Action": {
                "op": "==",
                "entity": { "type": "Action", "id": "view" }
            },
            "Resource": {
                "op": "in",
                "entity": { "type": "Folder", "id": "abc" }
            },
            "Conditions": [
                {
                    "kind": "when",
                    "body": {
                        "==": {
                            "left": {
                                ".": {
                                    "left": {
                                        "Var": "context"
                                    },
                                    "attr": "tls_version"
                                }
                            },
                            "right": {
                                "Value": "1.3"
                            }
                        }
                    }
                }
            ]
        }
        "#;

        let jstr = env.new_string(invalid_input).unwrap();
        let result = from_json_internal(&mut env, jstr);
        assert!(result.is_err(), "Expected json parsing to fail: {:?}", result);    
    
    }

   

        #[test]
        fn to_json_internal_test() {
            let mut env = JVM.attach_current_thread().unwrap();
            let input = r#"permit(principal, action, resource);"#;
            let jstr = env.new_string(input).unwrap();
            let result = to_json_internal(&mut env, jstr);

            assert!(result.is_ok(), "Valid json");
        }

        #[test]
        fn to_json_internal_invalid() {
            let mut env = JVM.attach_current_thread().unwrap();
            let invalid_input = r#"Permit(Principal, Resource, Action);"#;
            let jstr = env.new_string(invalid_input).unwrap();

        let result = from_json_internal(&mut env, jstr);
        assert!(result.is_err(), "Expected json_internal parsing to fail: {:?}", result);    }
        
    }
    mod map_tests {
        use super::*;

        #[test]
        fn map_new_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            let java_hash_map = Map::<JString, JString>::new(&mut env);

            assert!(java_hash_map.is_ok(), "Map creation should succeed");

            assert!(
                env.is_instance_of(java_hash_map.unwrap().into_inner(), "java/util/HashMap")
                    .unwrap(),
                "Object should be a HashMap instance."
            );
        }

        #[test]
        fn map_put_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            let mut java_hash_map = Map::<JString, JString>::new(&mut env).unwrap();

            let key = env.new_string("test_key").unwrap();
            let value = env.new_string("test_value").unwrap();

            let result = java_hash_map.put(&mut env, key, value);

            assert!(result.is_ok(), "Map put should succeed.");

            let new_key = env.new_string("test_key").unwrap();
            let new_value = env.new_string("updated_value").unwrap();

            let update_result = java_hash_map.put(&mut env, new_key, new_value);

            assert!(result.is_ok(), "Map put should succeed.");

            let update_result_jstr = JString::cast(&mut env, update_result.unwrap()).unwrap();
            let update_result_str = String::from(env.get_string(&update_result_jstr).unwrap());

            assert_eq!(
                update_result_str, "test_value",
                "Value returned from map update should match the original value of test_key."
            )
        }

        #[test]
        fn map_get_tests() {
            let mut env = JVM.attach_current_thread().unwrap();
            let mut java_hash_map = Map::<JString, JString>::new(&mut env).unwrap();

            let key = env.new_string("test_key").unwrap();
            let value = env.new_string("test_value").unwrap();

            let _ = java_hash_map.put(&mut env, key, value);

            let retrieval_key = env.new_string("test_key").unwrap();
            let retrieved_value = java_hash_map.get(&mut env, retrieval_key).unwrap();

            let retrieved_value_jstr = JString::cast(&mut env, retrieved_value).unwrap();
            let retrieved_value_str = String::from(env.get_string(&retrieved_value_jstr).unwrap());

            assert_eq!(
                retrieved_value_str, "test_value",
                "Retrieved value should be equal to the inserted value."
            )
        }
        #[test]
        fn test_parse_cedar_schema_internal_invalid() {
            let mut env = JVM.attach_current_thread().unwrap();

            let invalid_input = "Not a valid input";
            let schema_jstr = env.new_string(invalid_input).unwrap();
            let result = parse_cedar_schema_internal(&mut env, schema_jstr);
            assert!(
                result.is_err(),
                "Expected parse_cedar_schema_internal to fail"
            );
        }
        #[test]
        fn parse_cedar_schema_internal_valid() {
            let mut env = JVM.attach_current_thread().unwrap();

            let input = r#"
        entity User = {
            name: String,
            age?: Long,
        };
        entity Photo in Album;
        entity Album;
        action view appliesTo {
            principal : [User],
            resource: [Album,Photo]
        }; 
    "#;

            let schema_jstr = env.new_string(input).unwrap();
            let result = parse_cedar_schema_internal(&mut env, schema_jstr);

            assert!(
                result.is_ok(),
                "Expected parse_cedar_schema_internal to succeed"
            );

            let jvalue = result.unwrap();
            let parsed_jstring = JString::cast(&mut env, jvalue.l().unwrap()).unwrap();
            let parsed_string = String::from(env.get_string(&parsed_jstring).unwrap());
            assert_eq!(parsed_string, "success");
        }

       
    }
    mod schema_test{
        use std::result;

        use cedar_policy::{EntityId, Schema};
        use super::*;

     #[test]
     fn parse_json_schema_internal_valid_test()
     {
        let mut env = JVM.attach_current_thread().unwrap();
        let input = r#" {
        "schema": {
            "entityTypes": {
            "User": {
                "memberOfTypes": ["Group"]
            },
            "Group": {},
            "File": {}
            },
            "actions": {
            "read": {
                "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["File"]
                }
            }
            }
        }
        }"#;
        let jstr = env.new_string(input).unwrap();
        let result = parse_json_schema_internal(&mut env, jstr);
        assert!(result.is_ok(), "successfully parsed json_schema_internal");

        let output = result.unwrap();
        let jstring_obj = output.l().unwrap();
        let jstring : jni::objects::JString = JString:: from(jstring_obj);
        let rust_output: String = env.get_string(&jstring).unwrap().into();
        assert_eq!(rust_output,"success");

     }
    
     #[test]
     fn parse_json_schema_internal_invalid_test()
     {
        let mut env = JVM.attach_current_thread().unwrap();
        let invalid_input = r#" {
        "Schema": {
            "entityTypes": {
            "User": {
                "MemberOfTypes": ["Group"]
            },
            "Group": {},
            "File": {}
            },
            "Actions": {
            "read": {
                "AppliesTo": {
                "principalTypes": ["User"],
                "AesourceTypes": ["File"]
                }
            }
            }
        }
        }"#;

        let jstr = env.new_string(invalid_input).unwrap();
        let result = parse_json_schema_internal(&mut env, jstr);
        assert!(result.is_err(), "Expected json_schema_internal parsing to fail: {:?}", result);     
    }
   
         #[test]
        fn test_parse_policies_set_text_map()
        {
            let input_policies = r#"permit(principal, action , resource);
            permit(principal,action,resource) when {principal has x && principal.x == 5};"#;

            let result = parse_policy_set_to_text_map(input_policies);

            assert!(result.is_ok())
        }

        #[test]
        fn test_parse_policies_set_map_invalid()
        {
            let invalid_policies =r#"permit(principal?, action? , resource);
            permit(principal,action,resource) if {principal has x && principal.x == 5};"#;

            let result = parse_policy_set_to_text_map(invalid_policies);
            assert!(result.is_err(),"Expected policy set to fail")
        }
        #[test]
        fn parse_policies_empty()
        {
            let input = "";
            let result = parse_policy_set_to_text_map(input).unwrap();

            let(policies,templates) = result;
            assert!(policies.is_empty());
            assert!(templates.is_empty())
        }
        #[test]
        fn parse_policy_set_to_text_map_static_policies()
        {
            let input =r#"
            permit(principal,action,resource);
            forbid(principal == User::"bob",action,resource);"#;
            let result = parse_policy_set_to_text_map(input).unwrap();

            let(policies,templates )= result;
            assert_eq!(policies.len(),2);

            let p1_found = policies.iter().any(|(id,src)| src.contains("permit")&& id.starts_with("policy"));
            let p2_found = policies.iter().any(|(id,src)| src.contains("forbid")&& src.contains("User::\"bob\"") && id.starts_with("policy"));

            assert!(p1_found);
            assert!(p2_found);

            assert!(templates.is_empty());
        }
          #[test]
fn  parse_policy_set_to_text_map_templates() {
    let input = r#"
        permit(principal,action,resource);
    "#;

    let result = parse_policy_set_to_text_map(input).unwrap();
    let (policies, templates) = result;

    assert_eq!(policies.len(), 1, "Expected 1 static policy.");
    assert!(templates.is_empty(), "Expected no templates.");

    let p1_found = policies.iter().any(|(_id, src)| src.contains("permit"));
    assert!(p1_found, "permit policy not found or content is incorrect.");
}
       

    
    #[test]
        fn get_entity_identifier_repr_internal_null_input() {
            let mut env = JVM.attach_current_thread().unwrap();
            let result = get_entity_identifier_repr_internal(&mut env, JObject::null());
            assert!(env.exception_check().unwrap());
            assert!(result.is_ok(),"Succeded passing get_entity_identifier_repr_internal_null");
        }
       
        
 
    #[test]
        fn template_effect_jni_internal_permit_test(){
            let mut env = JVM.attach_current_thread().unwrap();
            let template_policy = r#"permit(principal==?principal,action == Action::"readfile",resource==?resource );"#;

            let jstr = env.new_string(template_policy).unwrap();
            let result = template_effect_jni_internal(&mut env, jstr);
            assert!(result.is_ok());

            let jvalue = result.unwrap();
            let jstring = JString::cast(&mut env, jvalue.l().unwrap()).unwrap();
            let effect = String::from(env.get_string(&jstring).unwrap());
            assert_eq!(effect, "permit");
        }

        #[test]
        fn template_effect_jni_internal_forbid_test() {
            let mut env = JVM.attach_current_thread().unwrap();
            let cedar_policy = r#"forbid(principal==?principal,action == Action::"readfile",resource==?resource );"#;
            let jstr = env.new_string(cedar_policy).unwrap();

            let result = template_effect_jni_internal(&mut env, jstr);
            assert!(result.is_ok());

            let jvalue = result.unwrap();
            let jstring = JString::cast(&mut env, jvalue.l().unwrap()).unwrap();
            let effect = String::from(env.get_string(&jstring).unwrap());

            assert_eq!(effect, "forbid");
        }

    #[test]
    fn parse_entity_uid_valid()
    {
        let mut env = JVM.attach_current_thread().unwrap();

        let input = r#"Foo::Bar::"alice""#;

        let jstr = env.new_string(input).unwrap();
        let result = parse_entity_uid_internal(&mut env, jstr);

        assert!(result.is_ok(),"Expected Entity_uid was successful");
    }
    #[test]
    fn parse_entity_uid_internal_invalid_test()

    {

        let mut env = JVM.attach_current_thread().unwrap();

        let invalid_input = r#"foo==\Alice\""#;


        let jstr = env.new_string(invalid_input).unwrap();

        let result = parse_entity_uid_internal(&mut env, jstr);

        assert!(result.is_err(),"Expected to parse_entity_uid_internal");

    }
     #[test]
        fn  parse_entity_uid_internal_invalid_syntax() {
            let mut env = JVM.attach_current_thread().unwrap();
            let input = "Invalid::\"uid"; 
            let jstr = env.new_string(input).unwrap();

            let result = parse_entity_uid_internal(&mut env, jstr);
            
            assert!(result.is_err(), "Expected an error for invalid EUID syntax.");
        }

    }
      
        

    

#[cfg(test)]
mod helper_tests {
    use std::result;

    use super::*;
    use cedar_policy::EntityId; 

    fn get_entity_identifier_string_representation(entity_id: &cedar_policy::EntityId) -> String {
        entity_id.escaped().to_string()
    }

    #[test]
    fn  get_entity_identifier_string_representation_simple() {
        let entity_id = EntityId::new("alice".to_string());
       
        let expected_repr = "alice".to_string();
        let actual_repr = get_entity_identifier_string_representation(&entity_id);
        assert_eq!(actual_repr, expected_repr);
    }

    #[test]
    fn  get_entity_identifier_string_representation_with_special_chars() {
        let entity_id = EntityId::new("al\\ice".to_string()); 
       
        let expected_repr = "al\\\\ice".to_string();
        let actual_repr = get_entity_identifier_string_representation(&entity_id);
        assert_eq!(actual_repr, expected_repr);
    }

    #[test]
    fn  get_entity_identifier_string_representation_empty() {
        let entity_id = EntityId::new("".to_string());
        
        let expected_repr = "".to_string();
        let actual_repr = get_entity_identifier_string_representation(&entity_id);
        assert_eq!(actual_repr, expected_repr);
    }

    #[test]
    fn  get_entity_identifier_string_representation_long_string() {
        let long_id = "a".repeat(1000); 
        let entity_id = EntityId::new(long_id.clone());
        
        let expected_repr = format!("{}", long_id);
        let actual_repr = get_entity_identifier_string_representation(&entity_id);
        assert_eq!(actual_repr, expected_repr);
    }

    #[test]
    fn parse_entity_type_name_internal_test()
    {
        let input = "User";
        let result = parse_entity_type_name_str(input).unwrap();
        assert_eq!(result.basename(),"User");
        assert!(result.namespace_components().next().is_none());
        assert_eq!(result.to_string(),"User")

    }

    #[test]
    fn parse_entity_type_name_valid_namespacestr()
    {
        let input = "PhotoApp::UserGroup::Admin";
        let result = parse_entity_type_name_str(input).unwrap();
        assert_eq!(result.basename(),"Admin");
        let namespace: Vec<&str> = result.namespace_components().collect();
        assert_eq!(namespace,vec!["PhotoApp","UserGroup"]);
        assert_eq!(result.to_string(),"PhotoApp::UserGroup::Admin");
    }
    #[test]
    fn parse_entity_type_name_emptystr()
    {
        let input ="";
        let result = parse_entity_type_name_str(input);
        assert!(result.is_err(),"Expected parsing failed due to an empty string");
    }
    #[test]
    fn parse_entity_type_name_separatorsstr()
    {
        let input = "::";
        let result = parse_entity_type_name_str(input);
        assert!(result.is_err(),"Expected parsing failed for only seperators");
    }
    #[test]
    fn  simple_entity_type_valid() {
        let input = "User";
        let result = parse_entity_type_name_str(input).unwrap();
        assert_eq!(result.basename().to_string(), "User");
        assert!(result.namespace().is_empty(), "Expected no namespace");
    }
    #[test]
    fn  valid_policy_formats_successfully() {
        let input = r#"
            permit(principal, action, resource);
        "#;
        let config = Config::default();

        let result = format_policies_str_with_config(input, &config);
        assert!(result.is_ok(), "Expected formatting to succeed");

        let output = result.unwrap();
        assert!(output.contains("permit"), "Expected output to include 'permit'");
    }
    #[test]
    fn  invalid_policy_returns_error() {
        let input = r#"
            permit(principal,, action, resource);
        "#;
        let config = Config::default();

        let result = format_policies_str_with_config(input, &config);
        assert!(result.is_err(), "Expected formatting to fail due to syntax error");
    }
     
         #[test]
fn  policies_str_to_pretty_internal_valid_policy_string() {
    let mut env = JVM.attach_current_thread().unwrap();
    
   
    let input = r#"permit(principal, action, resource);"#;
    let policies_jstr = env.new_string(input).unwrap();

    let result = policies_str_to_pretty_internal(&mut env, policies_jstr, None);
    assert!(result.is_ok(), "Expected valid policy string to format successfully.");

    let formatted_jvalue = result.unwrap();
    let jstring_obj: jni::objects::JString = formatted_jvalue.l().unwrap().into();
    let formatted_str: String = env.get_string(&jstring_obj).unwrap().into();

    assert!(formatted_str.contains("permit"), "Expected output to contain 'permit'.");
    assert!(formatted_str.contains("(") && formatted_str.contains(")"), "Expected parentheses in formatted output.");
}
        #[test]
        fn  parse_entity_type_name_internal_null_input() {
            let mut env = JVM.attach_current_thread().unwrap();
            
            let result = parse_entity_type_name_internal(&mut env, jni::objects::JString::from(jni::objects::JObject::null()));

            assert!(env.exception_check().unwrap());
            assert!(result.is_ok());
        }
         #[test]
        fn  parse_entity_type_name_internal_invalid() {
            let mut env = JVM.attach_current_thread().unwrap();
            let input_jstr = env.new_string("Invalid::Type!").unwrap(); 

            let result = parse_entity_type_name_internal(&mut env, input_jstr);
            assert!(result.is_err(), "Expected error for invalid entity type name input");
        }
             

    #[test]
    fn  parse_entity_type_name_str_valid_simple() {
        let input = "User";
        let result = parse_entity_type_name_str(input); 
        assert!(result.is_ok(), "Expected valid parse for 'User' in pure Rust test."); 
        let parsed_etype = result.unwrap();
        assert_eq!(parsed_etype.basename(), "User");
        assert!(parsed_etype.namespace_components().next().is_none());
    }

    #[test]
    fn build_java_policy_empty()
    {
        let mut env = JVM.attach_current_thread().unwrap();
        let entries : Vec<(String,String)> = vec![];

        let result = build_java_policy_set(&mut env, entries);
        assert!(result.is_ok()); 
    }
}
}






    