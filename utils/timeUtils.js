// utils/timeUtils.js
export const getCurrentIST = () => {
  const now = new Date();
  // Convert to IST (UTC+5:30)
  const istOffset = 5.5 * 60 * 60 * 1000; // 5 hours 30 minutes in milliseconds
  const istTime = new Date(now.getTime() + istOffset);
  return istTime;
};

export const timeToMinutesIST = (timeStr) => {
  const [hours, minutes] = timeStr.split(':').map(Number);
  return hours * 60 + minutes;
};

export const isWithinActiveHoursIST = (startTime, endTime) => {
  const now = getCurrentIST();
  const currentMinutes = timeToMinutesIST(
    now.toTimeString().slice(0, 8) // HH:MM:SS format
  );
  const startMinutes = timeToMinutesIST(startTime);
  const endMinutes = timeToMinutesIST(endTime);

  console.log('🕒 IST Active Hours Check:', {
    currentIST: now.toTimeString().slice(0, 8),
    startTime,
    endTime,
    currentMinutes,
    startMinutes,
    endMinutes
  });

  // Handle overnight active hours (e.g., 22:00 - 06:00)
  if (endMinutes < startMinutes) {
    return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
  }
  
  return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
};