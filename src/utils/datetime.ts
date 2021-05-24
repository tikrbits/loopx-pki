export namespace dt {
  export type TimeUnit = 'years' | 'months' | 'weeks' | 'days' | 'hours' | 'minutes' | 'seconds' | 'milliseconds';

  /**
   * Parse the given `str` and return milliseconds.
   *
   * @param {String} str
   * @return {Number}
   * @api private
   */

  function parse(str: string): [number, TimeUnit?] {
    str = String(str);
    if (str.length > 100) {
      return [-1];
    }
    const match =
      /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        str,
      );
    if (!match) {
      return [-1];
    }
    const n = parseFloat(match[1]);
    const type = (match[2] || 'ms').toLowerCase();
    switch (type) {
      case 'years':
      case 'year':
      case 'yrs':
      case 'yr':
      case 'y':
        return [n, 'years'];
      case 'minutes':
      case 'minute':
      case 'mins':
      case 'min':
      case 'm':
        return [n, 'months'];
      case 'weeks':
      case 'week':
      case 'w':
        return [n, 'weeks'];
      case 'days':
      case 'day':
      case 'd':
        return [n, 'days'];
      case 'hours':
      case 'hour':
      case 'hrs':
      case 'hr':
      case 'h':
        return [n, 'hours'];
      case 'seconds':
      case 'second':
      case 'secs':
      case 'sec':
      case 's':
        return [n, 'seconds'];
      case 'milliseconds':
      case 'millisecond':
      case 'msecs':
      case 'msec':
      case 'ms':
        return [n, 'milliseconds'];
      default:
        return [-1];
    }
  }

  export function add(date: Date, duration: string): Date;
  export function add(date: Date, n: number, unit: TimeUnit): Date;
  export function add(date: Date, n: number | string, unit?: TimeUnit): Date {
    if (typeof n === 'string') {
      [n, unit] = parse(n);
    }
    unit = unit ?? 'milliseconds';

    const fn = TimeAddFns[unit];
    if (!fn) {
      throw new Error('Unsupported unit: ' + unit);
    }
    return fn(date, n);
  }

  const TimeAddFns: {[unit in TimeUnit]: (date: Date, n: number) => Date} = {
    years: addYears,
    months: addMonths,
    weeks: addWeeks,
    days: addDays,
    hours: addHours,
    minutes: addMinutes,
    seconds: addSeconds,
    milliseconds: addMilliseconds,
  };

  /**
   * adding years
   * @param {Date} dateObj - a date object
   * @param {number} years - number of years to add
   * @returns {Date} a date after adding the value
   */
  export function addYears(dateObj: Date, years: number) {
    return addMonths(dateObj, years * 12);
  }

  /**
   * adding months
   * @param {Date} dateObj - a date object
   * @param {number} months - number of months to add
   * @returns {Date} a date after adding the value
   */
  export function addMonths(dateObj: Date, months: number) {
    const d = new Date(dateObj.getTime());

    d.setMonth(d.getMonth() + months);
    return d;
  }

  export function addWeeks(dateObj: Date, weeks: number) {
    return addDays(dateObj, weeks * 7);
  }

  /**
   * adding days
   * @param {Date} dateObj - a date object
   * @param {number} days - number of days to add
   * @returns {Date} a date after adding the value
   */
  export function addDays(dateObj: Date, days: number) {
    const d = new Date(dateObj.getTime());

    d.setDate(d.getDate() + days);
    return d;
  }

  /**
   * adding hours
   * @param {Date} dateObj - a date object
   * @param {number} hours - number of hours to add
   * @returns {Date} a date after adding the value
   */
  export function addHours(dateObj: Date, hours: number) {
    return addMilliseconds(dateObj, hours * 3600000);
  }

  /**
   * adding minutes
   * @param {Date} dateObj - a date object
   * @param {number} minutes - number of minutes to add
   * @returns {Date} a date after adding the value
   */
  export function addMinutes(dateObj: Date, minutes: number) {
    return addMilliseconds(dateObj, minutes * 60000);
  }

  /**
   * adding seconds
   * @param {Date} dateObj - a date object
   * @param {number} seconds - number of seconds to add
   * @returns {Date} a date after adding the value
   */
  export function addSeconds(dateObj: Date, seconds: number) {
    return addMilliseconds(dateObj, seconds * 1000);
  }

  /**
   * adding milliseconds
   * @param {Date} dateObj - a date object
   * @param {number} milliseconds - number of milliseconds to add
   * @returns {Date} a date after adding the value
   */
  export function addMilliseconds(dateObj: Date, milliseconds: number) {
    return new Date(dateObj.getTime() + milliseconds);
  }

  /**
   * subtracting
   * @param {Date} date1 - a Date object
   * @param {Date} date2 - a Date object
   * @returns {Object} a result object subtracting date2 from date1
   */
  export function subtract(date1: Date, date2: Date) {
    const delta = date1.getTime() - date2.getTime();

    return {
      toMilliseconds: function () {
        return delta;
      },
      toSeconds: function () {
        return (delta / 1000) | 0;
      },
      toMinutes: function () {
        return (delta / 60000) | 0;
      },
      toHours: function () {
        return (delta / 3600000) | 0;
      },
      toDays: function () {
        return (delta / 86400000) | 0;
      },
    };
  }
}
