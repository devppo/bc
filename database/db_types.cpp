#include "db_types.h"

Amount::Amount() : high(0), low(0) {}
Amount::Amount(uint32_t h, uint64_t l) : high(h), low(l) {}

bool Amount::operator < (const Amount &a) {
	if (this->high < a.high) return true;
	if (this->high == a.high) return this->low < a.low;
	return false;
}

bool Amount::operator > (const Amount &a) {
	if (this->high > a.high) return true;
	if (this->high == a.high) return this->low > a.low;
	return false;
}

bool Amount::operator != (const Amount &a) {
	return !(*this == a);
}

bool Amount::operator == (const Amount &a) {
	return (this->high == a.high) && (this->low == a.low);
}

Amount &Amount::operator = (const Amount &a) {
	if(*this != a) {
		this->high = a.high;
		this->low = a.low;
	}
	return *this;
}

Amount Amount::operator + (const Amount &a) {
	auto h = this->high + a.high;
	auto l = this->low + a.low;
	if (l >= 1000000000) {
		l -= 1000000000;
		++h;
	}
	return Amount{h, l};
}

Amount Amount::operator - (const Amount &a) {
	if(*this < a) throw(std::out_of_range("Negative amount detected")); //< нельзя уйти в отрицательное значение
	uint32_t h = this->high - a.high;
	uint64_t l = this->low;
	if (a.low > this->low) {
		l += 1000000000;
		--h;
	}
	l -= a.low;
	return Amount{h, l};
}

Amount Amount::operator -= (const Amount &a) {
	return *this = *this - a;
}

Amount Amount::operator += (const Amount &a) {
	return *this = *this + a;
}

Amount Amount::get_fee() {
	static uint16_t fee_ratio = FEE_RATIO;
	static uint32_t fee_ratio_l = FRACTION_RANK / FEE_RATIO;
	auto h = this->high / fee_ratio;
	auto l = this->high % fee_ratio * fee_ratio_l + this->low / fee_ratio;
	auto a = Amount{h, l};
	return (a < MINIMAL_COMISSION) ? MINIMAL_COMISSION : a;
}

