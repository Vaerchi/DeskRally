package controlplane

// Scheduled access windows (docs/57): a membership that grants only during set hours on set days in a
// time zone. The predicate here is mirrored by the SQL function membership_window_open (migration
// 0063); TestAccessWindowGoAndPgAgree runs one table of vectors through both.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // the alpine runtime image has no zoneinfo; LoadLocation must work anywhere
)

// AccessWindow limits a membership to [Start, End) local wall-clock minutes on Days, in Zone. Days is a
// bitmask, bit d = weekday d with 0 = Sunday (time.Weekday and pg extract(dow) agree). End <= Start
// crosses midnight: open from Start on a listed day until End on the following day.
type AccessWindow struct {
	Days  uint8
	Start int // minutes after local midnight, 0..1439
	End   int // 1..1440
	Zone  string

	loc *time.Location
}

var weekdayKeys = [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// timeZoneName is an IANA-style name: rejects POSIX TZ strings ("EST5EDT,M3.2.0,...") and bare offsets
// ("+05"), which pg would read with an inverted sign.
var timeZoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$`)

// ErrUnknownTimeZone is a time zone the database cannot evaluate (docs/57 sec. 4).
var ErrUnknownTimeZone = errors.New("unknown time zone")

// NewAccessWindow validates and builds a window.
func NewAccessWindow(days uint8, start, end int, zone string) (*AccessWindow, error) {
	if days == 0 || days > 127 {
		return nil, errors.New("days must name at least one weekday")
	}
	if start < 0 || start > 1439 || end < 1 || end > 1440 {
		return nil, errors.New("start must be 00:00-23:59 and end 00:01-24:00")
	}
	if start == end {
		return nil, errors.New("start and end must differ")
	}
	loc, err := loadZone(zone)
	if err != nil {
		return nil, err
	}
	return &AccessWindow{Days: days, Start: start, End: end, Zone: zone, loc: loc}, nil
}

func loadZone(zone string) (*time.Location, error) {
	if zone == "Local" || len(zone) > 64 || !timeZoneName.MatchString(zone) {
		return nil, ErrUnknownTimeZone
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return nil, ErrUnknownTimeZone
	}
	return loc, nil
}

func (w *AccessWindow) hasDay(d time.Weekday) bool { return w.Days&(1<<uint(d)) != 0 }

// OpenAt reports whether the window is open at t (docs/57 sec. 2). A nil window is always open.
func (w *AccessWindow) OpenAt(t time.Time) bool {
	if w == nil {
		return true
	}
	loc := w.loc
	if loc == nil {
		var err error
		if loc, err = loadZone(w.Zone); err != nil {
			return false // fail closed, like pg's AT TIME ZONE raising
		}
	}
	l := t.In(loc)
	d, m := l.Weekday(), l.Hour()*60+l.Minute()
	if w.Start < w.End {
		return w.hasDay(d) && w.Start <= m && m < w.End
	}
	return (w.hasDay(d) && m >= w.Start) || (w.hasDay((d+6)%7) && m < w.End)
}

func sameWindow(a, b *AccessWindow) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Days == b.Days && a.Start == b.Start && a.End == b.End && a.Zone == b.Zone
}

// accessWindowJSON is the API shape: {"days":["mon",...],"start":"08:00","end":"18:00","time_zone":"Europe/London"}.
type accessWindowJSON struct {
	Days     []string `json:"days"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	TimeZone string   `json:"time_zone"`
}

func formatClock(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

// MarshalJSON renders the API shape (days Sunday-first, the pg bit order).
func (w AccessWindow) MarshalJSON() ([]byte, error) {
	out := accessWindowJSON{Days: []string{}, Start: formatClock(w.Start), End: formatClock(w.End), TimeZone: w.Zone}
	for d := 0; d < 7; d++ {
		if w.Days&(1<<uint(d)) != 0 {
			out.Days = append(out.Days, weekdayKeys[d])
		}
	}
	return json.Marshal(out)
}

// parseClock reads "HH:MM"; 24:00 only when allow24.
func parseClock(s string, allow24 bool) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, m := 0, 0
	for i, c := range s {
		if i == 2 {
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		if i < 2 {
			h = h*10 + int(c-'0')
		} else {
			m = m*10 + int(c-'0')
		}
	}
	if m > 59 || h > 24 || (h == 24 && (m != 0 || !allow24)) {
		return 0, false
	}
	return h*60 + m, true
}

// ParseAccessWindow decodes and validates the API shape.
func ParseAccessWindow(raw json.RawMessage) (*AccessWindow, error) {
	var in accessWindowJSON
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, errors.New("access_window must be an object with days, start, end and time_zone")
	}
	var days uint8
	for _, k := range in.Days {
		i := -1
		for d, key := range weekdayKeys {
			if k == key {
				i = d
			}
		}
		if i < 0 || days&(1<<uint(i)) != 0 {
			return nil, errors.New("access_window.days must be distinct values of sun mon tue wed thu fri sat")
		}
		days |= 1 << uint(i)
	}
	start, ok := parseClock(in.Start, false)
	if !ok {
		return nil, errors.New("access_window.start must be HH:MM, 00:00-23:59")
	}
	end, ok := parseClock(in.End, true)
	if !ok || end == 0 {
		return nil, errors.New("access_window.end must be HH:MM, 00:01-24:00")
	}
	w, err := NewAccessWindow(days, start, end, in.TimeZone)
	if errors.Is(err, ErrUnknownTimeZone) {
		return nil, errors.New("access_window.time_zone must be an IANA time zone name, such as Europe/London")
	}
	if err != nil {
		return nil, fmt.Errorf("access_window: %w", err)
	}
	return w, nil
}
