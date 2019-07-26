/*
 * Copyright 2019 Google Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OPEN_SOURCE_SERVER_LIB_H_
#define OPEN_SOURCE_SERVER_LIB_H_

#include "crypto/context.h"
#include "crypto/paillier.h"
#include "match.pb.h"
#include "util/status.inc"
#include "crypto/ec_commutative_cipher.h"
#include "absl/time/time.h"
#include <map>

namespace private_join_and_compute {

// The "server side" of the intersection-sum protocol.  This represents the
// party that will receive the size of the intersection as its output.  The
// values that will be summed are supplied by the other party; this party will
// only supply set elements as its inputs.
class Server {
 public:
  Server(::private_join_and_compute::Context* ctx, const std::vector<std::string>& inputs);

  // This constructor allows an object to be instantiated from a previously
  // serialized state.
  Server(::private_join_and_compute::Context* ctx, const std::string& serialized_state);
  ~Server() = default;

  // The protocol begins with this party sending its encrypted set to the client
  // party.
  ::util::StatusOr<ServerRoundOne> EncryptSet();

  // This is where the intersection-sum is computed.  The sum will be computed
  // using the Paillier homomorphism and will be returned to the client party
  // for decryption, together with the size of the intersection.
  ::util::StatusOr<ServerRoundTwo> ComputeIntersection(
      const ClientRoundOne& client_message);

  ::private_join_and_compute::ECCommutativeCipher* GetECCipher() { return ec_cipher_.get(); }

  std::string GetSerializedState() const;

  // Stats
  const std::map<std::string, absl::Duration>& GetAllStats() const { return stats_;}
  const std::vector<std::string>& GetStatsKeysInOrder() const { return stats_keys_;}
  void AddStat(std::string k, absl::Duration v) { stats_keys_.push_back(k); stats_[k] = v;}
  absl::Duration GetStat(const std::string k) const { return stats_.find(k)->second;}

 private:
  ::private_join_and_compute::Context* ctx_;  // not owned
  std::unique_ptr<ECCommutativeCipher> ec_cipher_;

  std::vector<std::string> inputs_;

  // stats
  std::map<std::string, absl::Duration> stats_;
  std::vector<std::string> stats_keys_;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_SERVER_LIB_H_
