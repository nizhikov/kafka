/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.security.authorizer;

import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.zk.ZkVersion;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

public class AclAuthorizer {
    // Optional override zookeeper cluster configuration where acls will be stored. If not specified,
    // acls will be stored in the same zookeeper where all other kafka broker metadata is stored.
    public static final String configPrefix = "authorizer.";
    private static final String ZkUrlProp = configPrefix + "zookeeper.url";
    private static final String ZkConnectionTimeOutProp = configPrefix + "zookeeper.connection.timeout.ms";
    private static final String ZkSessionTimeOutProp = configPrefix + "zookeeper.session.timeout.ms";
    private static final String ZkMaxInFlightRequests = configPrefix + "zookeeper.max.in.flight.requests";

    // Semi-colon separated list of users that will be treated as super users and will have access to all the resources
    // for all actions from all hosts, defaults to no super users.
    public static final String SuperUsersProp = "super.users";
    // If set to true when no acls are found for a resource, authorizer allows access to everyone. Defaults to false.
    public static final String AllowEveryoneIfNoAclIsFoundProp = "allow.everyone.if.no.acl.found";

    public static class VersionedAcls {
        public final Set<AclEntry> acls;
        public final int zkVersion;

        public VersionedAcls(Set<AclEntry> acls, int zkVersion) {
            this.acls = acls;
            this.zkVersion = zkVersion;
        }

        boolean exists() {
            return zkVersion != ZkVersion.UNKNOWN_VERSION;
        }
    }

    private static class AclSeqs{
        final Collection<Collection<AclEntry>> seqs;

        public AclSeqs(Collection<Collection<AclEntry>> seqs) {
            this.seqs = seqs;
        }

        public Optional<AclEntry> find(Predicate<AclEntry> p) {
            // Lazily iterate through the inner `Seq` elements and stop as soon as we find a match
            for (Collection<AclEntry> seq : seqs) {
                for (AclEntry aclEntry : seq) {
                    if (p.test(aclEntry))
                        return Optional.of(aclEntry);
                }
            }
            return Optional.empty();
        }

        public boolean isEmpty() {
            for (Collection<AclEntry> seq : seqs) {
                if (!seq.isEmpty())
                    return true;
            }
            return false;
        }
    }

    public static final VersionedAcls NoAcls = new VersionedAcls(Collections.emptySet(), ZkVersion.UNKNOWN_VERSION);
    public static final String WildcardHost = "*";

    // Orders by resource type, then resource pattern type and finally reverse ordering by name.
    public static class ResourceOrdering implements Comparator<ResourcePattern> {
        @Override
        public int compare(ResourcePattern a, ResourcePattern b) {
            int rt = a.resourceType().compareTo(b.resourceType());
            if (rt != 0)
                return rt;
            else {
                int rnt = a.patternType().compareTo(b.patternType());
                if (rnt != 0)
                    return rnt;
                else
                    return (a.name().compareTo(b.name())) * -1;
            }
        }
    }

    private void validateAclBinding(AclBinding aclBinding) {
        if (aclBinding.isUnknown())
            throw new IllegalArgumentException("ACL binding contains unknown elements");
        if (aclBinding.pattern().name().contains("/"))
            throw new IllegalArgumentException("ACL binding contains invalid resource name: " + aclBinding.pattern().name());
    }
}
