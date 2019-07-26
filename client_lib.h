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

#ifndef OPEN_SOURCE_CLIENT_LIB_H_
#define OPEN_SOURCE_CLIENT_LIB_H_

#include "crypto/context.h"
#include "crypto/paillier.h"
#include "match.pb.h"
#include "util/status.inc"
#include "crypto/ec_commutative_cipher.h"
#include "absl/time/time.h"
#include <map>

namespace private_join_and_compute {

// This class represents the "client" part of the intersection-sum protocol,
// which supplies the associated values that will be used to compute the sum.
// This is the party that will receive the sum as output.
class Client {
 public:
  Client(Context* ctx, const std::vector<std::string>& elements,
         const std::vector<BigNum>& values, int32_t modulus_size);
  Client(Context* ctx, const std::string& serialized);

  // The server sends the first message of the protocol, which contains its
  // encrypted set.  This party then re-encrypts that set and replies with the
  // reencrypted values and its own encrypted set.
  ::util::StatusOr<ClientRoundOne> ReEncryptSet(
      const ServerRoundOne& server_message);

  // After the server computes the intersection-sum, it will send it back to
  // this party for decryption, together with the intersection_size. This party
  // will decrypt and output the intersection sum and intersection size.
  ::util::StatusOr<std::pair<int64_t, BigNum>> DecryptSum(
      const ServerRoundTwo& server_message);

  std::string GetSerializedState() const;

    // Stats
  const std::map<std::string, absl::Duration>& GetAllStats() const { return stats_;}
  const std::vector<std::string>& GetStatsKeysInOrder() const { return stats_keys_;}
  void AddStat(std::string k, absl::Duration v) { stats_keys_.push_back(k); stats_[k] = v;}
  absl::Duration GetStat(const std::string k) const { return stats_.find(k)->second;}

 private:
  Context* ctx_;  // not owned
  std::vector<std::string> elements_;
  std::vector<BigNum> values_;

  // The Paillier private key
  BigNum p_, q_;

  std::unique_ptr<ECCommutativeCipher> ec_cipher_;
  std::unique_ptr<PrivatePaillier> private_paillier_;

  // stats
  std::map<std::string, absl::Duration> stats_;
  std::vector<std::string> stats_keys_;};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_CLIENT_LIB_H_
