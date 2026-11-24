#pragma once

#include "generated_policy.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace mcp_lattice {

struct LatticeState {
    std::uint64_t taint{0};
    bool halted{false};
};

struct StepResult {
    LatticeState next;
    bool allowed;
    std::string_view reason;
};

[[nodiscard]] constexpr StepResult transition(
    LatticeState s,
    std::uint64_t taint_mask,
    std::uint64_t clearance_mask
) noexcept {
    if (s.halted) {
        return {{s.taint, true}, false, "HALTED: session permanently terminated"};
    }
    if ((s.taint & ~clearance_mask) != 0ULL) {
        return {{s.taint, true}, false, "POLICY VIOLATION: exfil/exec blocked by active taint lattice"};
    }
    return {{s.taint | taint_mask, false}, true, "Allowed by lattice policy"};
}

[[nodiscard]] constexpr std::optional<policy::ToolRule> lookup_rule(
    std::string_view tool_name
) noexcept {
    for (const auto& r : policy::RULES) {
        if (r.name == tool_name) {
            return r;
        }
    }
    return std::nullopt;
}

class LatticeEngine {
private:
    LatticeState state_{0ULL, false};

public:
    constexpr LatticeEngine() noexcept = default;

    LatticeEngine(const LatticeEngine&) = delete;
    LatticeEngine& operator=(const LatticeEngine&) = delete;
    LatticeEngine(LatticeEngine&&) = delete;
    LatticeEngine& operator=(LatticeEngine&&) = delete;

    [[nodiscard]] constexpr LatticeState state() const noexcept {
        return state_;
    }

    [[nodiscard]] constexpr StepResult step_masks(
        std::uint64_t taint_mask,
        std::uint64_t clearance_mask
    ) & noexcept {
        const auto res = transition(state_, taint_mask, clearance_mask);
        state_ = res.next;
        return res;
    }

    [[nodiscard]] constexpr StepResult inspect_tool(
        std::string_view tool_name,
        bool is_sensitive_read = false
    ) & noexcept {
        const auto rule = lookup_rule(tool_name);
        if (!rule.has_value()) {
            state_.halted = true;
            return {state_, false, "POLICY VIOLATION: unknown tool denied (fail-closed)"};
        }
        std::uint64_t effective_taint = rule->taint_mask;
        if (tool_name == "read_file" && is_sensitive_read) {
            effective_taint |= policy::LABEL_SECRETS;
        }
        return step_masks(effective_taint, rule->clearance_mask);
    }
};

} // namespace mcp_lattice
